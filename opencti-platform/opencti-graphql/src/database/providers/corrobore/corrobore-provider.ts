import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { FilterMode, FilterOperator, type Filter, type FilterGroup } from '../../../generated/graphql';
import type { AuthContext, AuthUser } from '../../../types/user';

export type CorroboreProviderConfig = {
  baseUrl: string;
  token?: string;
  tokenFile?: string;
  timeoutMs: number;
};

export type CorroboreAccessContext = {
  subject_id: string;
  organization_ids?: string[];
  marking_ids?: string[];
  tenant_id?: string | null;
  roles?: string[];
  attributes?: Record<string, string>;
};

export type CorroboreOperation = {
  operation: string;
  request: unknown;
};

export type CorroboreRequestContext = {
  requestId: string;
  correlationId: string;
  idempotencyKey?: string;
  access: CorroboreAccessContext;
};

type CorroboreRuntimeVersion = {
  opencti_mode?: string;
  version?: string;
};

const REQUIRED_RUNTIME_CAPABILITIES = [
  'initialize', 'get_by_id', 'list', 'paginate', 'search', 'count', 'aggregate',
  'create', 'update', 'delete', 'bulk', 'merge',
] as const;

export type CorroboreRecordPage = {
  records: Array<{ id: string; kind: string; revision: number; body: Record<string, unknown> }>;
  next_token: string | null;
  total_count: number | null;
};

type CorroborePredicate
  = | { operator: 'condition'; arguments: CorroboreCondition }
    | { operator: 'and' | 'or'; arguments: CorroborePredicate[] }
    | { operator: 'nested'; arguments: { path: string; predicate: CorroborePredicate } };

type CorroboreCondition = {
  field: string;
  operator: string;
  value: unknown;
};

type CorroboreFilter = Filter & { nested?: CorroboreFilter[] };
type CorroboreFilterGroup = Omit<FilterGroup, 'filters' | 'filterGroups'> & {
  filters: CorroboreFilter[];
  filterGroups: CorroboreFilterGroup[];
};

type CorroboreSuccess = {
  response: string;
  data: any;
};

type CorroboreEnvelope = {
  outcome?: {
    status?: string;
    response?: CorroboreSuccess;
    error?: { code?: string; message?: string; retryable?: boolean };
  };
};

export class CorroboreProviderError extends Error {
  code: string;
  retryable: boolean;

  constructor(code: string, message: string, retryable: boolean) {
    super(message);
    this.name = 'CorroboreProviderError';
    this.code = code;
    this.retryable = retryable;
  }
}

const required = (value: string | undefined, name: string): string => {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${name} is required`);
  }
  return value.trim();
};

/** Parse and validate only the configuration accepted by the Corrobore provider. */
export const parseCorroboreConfig = (env: NodeJS.ProcessEnv | Record<string, string | undefined>): CorroboreProviderConfig => {
  if (env.DATABASE_ENGINE !== 'corrobore') {
    throw new Error(`Unsupported DATABASE_ENGINE=${env.DATABASE_ENGINE ?? ''}`);
  }
  const elasticVariables = Object.keys(env).filter((name) => name.startsWith('ELASTICSEARCH__')).sort();
  if (elasticVariables.length > 0) {
    throw new Error(`Elastic-free mode rejects ${elasticVariables.join(', ')}`);
  }
  if (env.CORROBORE__AUTH_TOKEN && env.CORROBORE__AUTH_TOKEN_FILE) {
    throw new Error('Set exactly one Corrobore authentication token source');
  }
  const token = env.CORROBORE__AUTH_TOKEN?.trim() || undefined;
  const tokenFile = env.CORROBORE__AUTH_TOKEN_FILE?.trim() || undefined;
  if (!token && !tokenFile) {
    throw new Error('CORROBORE__AUTH_TOKEN or CORROBORE__AUTH_TOKEN_FILE is required');
  }
  const timeoutMs = Number(env.CORROBORE__TIMEOUT_MS ?? 30000);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error('CORROBORE__TIMEOUT_MS must be a positive integer');
  }
  return {
    baseUrl: required(env.CORROBORE__URL, 'CORROBORE__URL').replace(/\/$/, ''),
    token,
    tokenFile,
    timeoutMs,
  };
};

/** Convert OpenCTI's authenticated user into provider-neutral authorization facts. */
export const accessContextFromUser = (user: Record<string, any>): CorroboreAccessContext => {
  const ids = (values: Array<Record<string, any>> | undefined): string[] => (values ?? [])
    .map((value) => value.internal_id ?? value.id)
    .filter((value): value is string => typeof value === 'string' && value.length > 0);
  const groupIds = ids(user.groups);
  const roles = (user.roles ?? [])
    .map((role: Record<string, any>) => role.name)
    .filter((role: unknown): role is string => typeof role === 'string' && role.length > 0);
  if ((user.capabilities ?? []).some((capability: Record<string, any>) => capability.name === 'BYPASS')) {
    roles.push('system');
  }
  return {
    subject_id: required(user.internal_id ?? user.id, 'OpenCTI user identity'),
    organization_ids: ids(user.organizations),
    marking_ids: ids(user.allowed_marking),
    tenant_id: typeof user.tenant_id === 'string' ? user.tenant_id : null,
    roles,
    attributes: groupIds.length > 0 ? { group_ids: JSON.stringify(groupIds) } : {},
  };
};

const conditionOperator = (filter: CorroboreFilter): string => {
  const multiple = filter.values.length > 1;
  switch (filter.operator ?? FilterOperator.Eq) {
    case FilterOperator.Eq: return multiple ? 'in' : 'equal';
    case FilterOperator.NotEq: return multiple ? 'not_in' : 'not_equal';
    case FilterOperator.Nil: return 'not_exists';
    case FilterOperator.NotNil: return 'exists';
    case FilterOperator.Gt: return 'greater_than';
    case FilterOperator.Gte: return 'greater_than_or_equal';
    case FilterOperator.Lt: return 'less_than';
    case FilterOperator.Lte: return 'less_than_or_equal';
    case FilterOperator.Wildcard: return 'wildcard';
    default: throw new CorroboreProviderError('unsupported_capability', `Unsupported OpenCTI filter operator ${filter.operator}`, false);
  }
};

const filterToPredicate = (filter: CorroboreFilter): CorroborePredicate => {
  const keys = Array.isArray(filter.key) ? filter.key : [filter.key];
  if (keys.length !== 1 || typeof keys[0] !== 'string' || keys[0].length === 0) {
    throw new CorroboreProviderError('unsupported_capability', 'Corrobore requires one typed field per filter', false);
  }
  if (filter.nested && filter.nested.length > 0) {
    const nested = filter.nested.map(filterToPredicate);
    return {
      operator: 'nested',
      arguments: {
        path: keys[0],
        predicate: nested.length === 1 ? nested[0] : { operator: 'and', arguments: nested },
      },
    };
  }
  const operator = conditionOperator(filter);
  const value = operator === 'exists' || operator === 'not_exists'
    ? null
    : filter.values.length > 1 ? filter.values : filter.values[0];
  return { operator: 'condition', arguments: { field: keys[0], operator, value } };
};

/** Preserve the boolean structure of OpenCTI filters without exposing Query DSL. */
export const filterGroupToPredicate = (filterGroup: CorroboreFilterGroup | null | undefined): CorroborePredicate | null => {
  if (!filterGroup) return null;
  const argumentsList = [
    ...filterGroup.filters.map(filterToPredicate),
    ...filterGroup.filterGroups.map((group) => filterGroupToPredicate(group)).filter((predicate): predicate is CorroborePredicate => predicate !== null),
  ];
  if (argumentsList.length === 0) return null;
  if (argumentsList.length === 1) return argumentsList[0];
  return {
    operator: filterGroup.mode === FilterMode.Or ? 'or' : 'and',
    arguments: argumentsList,
  };
};

/** Build the OpenCTI GraphQL connection while keeping Corrobore cursors opaque. */
export const recordPageToConnection = (page: CorroboreRecordPage) => {
  const cursor = page.next_token ?? '';
  const edges = page.records.map((record) => ({ cursor, node: record.body }));
  return {
    edges,
    pageInfo: {
      startCursor: edges.length > 0 ? cursor : '',
      endCursor: edges.length > 0 ? cursor : '',
      hasNextPage: page.next_token !== null,
      hasPreviousPage: false,
      globalCount: page.total_count ?? page.records.length,
    },
  };
};

/** Authenticated HTTP implementation of the versioned Knowledge Data Engine contract. */
export class CorroboreProviderClient {
  private readonly config: CorroboreProviderConfig;
  private readonly fetchImplementation: typeof fetch;
  private token?: string;

  constructor(config: CorroboreProviderConfig, fetchImplementation: typeof fetch = globalThis.fetch) {
    if (typeof fetchImplementation !== 'function') throw new Error('A Fetch API implementation is required');
    this.config = { ...config, baseUrl: required(config.baseUrl, 'Corrobore base URL').replace(/\/$/, '') };
    this.fetchImplementation = fetchImplementation;
    this.token = config.token;
  }

  async initialize(): Promise<CorroboreRuntimeVersion> {
    if (this.config.token && this.config.tokenFile) {
      throw new Error('Set exactly one Corrobore authentication token source');
    }
    if (this.config.tokenFile) {
      this.token = required(await readFile(this.config.tokenFile, 'utf8'), 'Corrobore token file');
    }
    this.token = required(this.token, 'Corrobore authentication token');
    const [health, version] = await Promise.all([
      this.request('/health/ready', 'GET'),
      this.request('/version', 'GET'),
    ]);
    if ((health as { ready?: boolean }).ready !== true) {
      throw new CorroboreProviderError('backend_unavailable', 'Corrobore is not ready', true);
    }
    if ((version as CorroboreRuntimeVersion).opencti_mode !== 'elastic_free') {
      throw new CorroboreProviderError('schema_incompatible', 'Corrobore is not running in elastic_free OpenCTI mode', false);
    }
    const negotiation = await this.read({ operation: 'initialize', request: {
      client_contract_version: { major: 1, minor: 0 },
      required_capabilities: REQUIRED_RUNTIME_CAPABILITIES,
    } }, {
      requestId: 'opencti-provider-initialize',
      correlationId: 'opencti-provider-initialize',
      access: {
        subject_id: 'system',
        organization_ids: [],
        marking_ids: [],
        tenant_id: null,
        roles: ['system'],
        attributes: {},
      },
    });
    if (negotiation.response !== 'initialized') {
      throw new CorroboreProviderError('schema_incompatible', 'Corrobore did not return provider capabilities', false);
    }
    const supported = new Set((negotiation.data?.capabilities ?? [])
      .filter((capability: any) => capability.status?.status === 'supported')
      .map((capability: any) => capability.operation));
    const missing = REQUIRED_RUNTIME_CAPABILITIES.filter((capability) => !supported.has(capability));
    if (missing.length > 0) {
      throw new CorroboreProviderError('unsupported_capability', `Corrobore is missing required capabilities: ${missing.join(', ')}`, false);
    }
    return version as CorroboreRuntimeVersion;
  }

  async read(operation: CorroboreOperation, context: CorroboreRequestContext): Promise<CorroboreSuccess> {
    return this.knowledgeRequest('/v1/opencti/reads', operation, context, true);
  }

  async write(operation: CorroboreOperation, context: CorroboreRequestContext): Promise<CorroboreSuccess> {
    if (!context.idempotencyKey) {
      throw new CorroboreProviderError('invalid_request', 'Corrobore writes require an idempotency key', false);
    }
    return this.knowledgeRequest('/v1/opencti/writes', operation, context, false);
  }

  async fileCommand(command: Record<string, unknown>): Promise<any> {
    return this.request('/v1/opencti/files', 'POST', command);
  }

  private async knowledgeRequest(
    path: string,
    operation: CorroboreOperation,
    context: CorroboreRequestContext,
    routed: boolean,
  ): Promise<CorroboreSuccess> {
    const request = {
      contract_version: { major: 1, minor: 0 },
      context: {
        request_id: context.requestId || randomUUID(),
        correlation_id: context.correlationId || context.requestId || randomUUID(),
        ...(context.idempotencyKey ? { idempotency_key: context.idempotencyKey } : {}),
        consistency: 'read_your_writes',
        access: context.access,
      },
      operation,
    };
    const payload = routed ? {
      request,
      metadata: { environment: 'production', organization_id: null, tenant_id: context.access.tenant_id ?? null, feature_flags: [] },
    } : request;
    const envelope = await this.request(path, 'POST', payload) as CorroboreEnvelope;
    if (envelope.outcome?.status === 'failure') {
      const failure = envelope.outcome.error;
      throw new CorroboreProviderError(
        failure?.code ?? 'internal',
        failure?.message ?? 'Corrobore rejected the operation',
        failure?.retryable ?? false,
      );
    }
    if (envelope.outcome?.status !== 'success' || !envelope.outcome.response) {
      throw new CorroboreProviderError('internal', 'Corrobore returned an invalid response envelope', false);
    }
    return envelope.outcome.response;
  }

  private async request(path: string, method: 'GET' | 'POST', body?: unknown): Promise<unknown> {
    const controller = new AbortController();
    const startedAt = Date.now();
    let rateLimitAttempt = 0;
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      while (true) {
        const response = await this.fetchImplementation(`${this.config.baseUrl}${path}`, {
          method,
          headers: {
            authorization: `Bearer ${required(this.token, 'Corrobore authentication token')}`,
            accept: 'application/json',
            ...(body === undefined ? {} : { 'content-type': 'application/json' }),
          },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: controller.signal,
        });
        if (response.status === 429) {
          const remainingMs = this.config.timeoutMs - (Date.now() - startedAt);
          if (remainingMs <= 0) {
            throw new CorroboreProviderError('backend_unavailable', `Corrobore ${method} ${path} remained rate limited`, true);
          }
          const retryAfterSeconds = Number(response.headers.get('retry-after'));
          const backoffMs = Number.isFinite(retryAfterSeconds) && retryAfterSeconds >= 0
            ? retryAfterSeconds * 1000
            : Math.min(50 * (2 ** Math.min(rateLimitAttempt, 5)), 1000);
          await new Promise((resolve) => {
            setTimeout(resolve, Math.min(Math.max(backoffMs, 1), remainingMs));
          });
          rateLimitAttempt += 1;
          continue;
        }
        if (!response.ok) {
          throw new CorroboreProviderError('backend_unavailable', `Corrobore ${method} ${path} failed with HTTP ${response.status}`, response.status >= 500);
        }
        return await response.json();
      }
    } finally {
      clearTimeout(timeout);
    }
  }
}

let runtimeClient: CorroboreProviderClient | undefined;
let runtimeVersion: CorroboreRuntimeVersion | undefined;

export const isCorroboreProviderConfigured = (env: NodeJS.ProcessEnv = process.env): boolean => env.DATABASE_ENGINE === 'corrobore';

export const initializeCorroboreProvider = async (env: NodeJS.ProcessEnv = process.env): Promise<boolean> => {
  const client = new CorroboreProviderClient(parseCorroboreConfig(env));
  runtimeVersion = await client.initialize();
  runtimeClient = client;
  return true;
};

export const corroboreProviderVersion = (): CorroboreRuntimeVersion => {
  if (!runtimeVersion) throw new CorroboreProviderError('backend_unavailable', 'Corrobore provider has not been initialized', true);
  return runtimeVersion;
};

const activeClient = (): CorroboreProviderClient => {
  if (!runtimeClient) throw new CorroboreProviderError('backend_unavailable', 'Corrobore provider has not been initialized', true);
  return runtimeClient;
};

export const corroboreRequestContext = (
  context: AuthContext,
  user: AuthUser,
  idempotencyKey?: string,
): CorroboreRequestContext => {
  const requestId = context.eventId ?? context.workId ?? randomUUID();
  return {
    requestId,
    correlationId: requestId,
    ...(idempotencyKey ? { idempotencyKey } : {}),
    access: accessContextFromUser(user),
  };
};

export const corroboreRead = (
  operation: CorroboreOperation,
  context: AuthContext,
  user: AuthUser,
): Promise<CorroboreSuccess> => activeClient().read(operation, corroboreRequestContext(context, user));

export const corroboreWrite = (
  operation: CorroboreOperation,
  context: AuthContext,
  user: AuthUser,
  idempotencyKey: string,
): Promise<CorroboreSuccess> => activeClient().write(operation, corroboreRequestContext(context, user, idempotencyKey));

export const corroboreFileCommand = (command: Record<string, unknown>): Promise<any> => activeClient().fileCommand(command);
