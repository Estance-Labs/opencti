import { describe, expect, it, vi } from 'vitest';
import {
  CorroboreProviderClient,
  accessContextFromUser,
  filterGroupToPredicate,
  parseCorroboreConfig,
  recordPageToConnection,
} from '../../../src/database/providers/corrobore/corrobore-provider';
import { FilterMode, FilterOperator } from '../../../src/generated/graphql';

const success = (response: string, data: unknown) => ({
  contract_version: { major: 1, minor: 0 },
  correlation_id: 'correlation--1',
  outcome: { status: 'success', response: { response, data } },
});

describe('Corrobore knowledge data provider', () => {
  it('requires the explicit provider configuration and rejects Elastic variables', () => {
    expect(parseCorroboreConfig({
      DATABASE_ENGINE: 'corrobore',
      CORROBORE__URL: 'https://corrobore:8080/',
      CORROBORE__AUTH_TOKEN: 'secret',
    })).toEqual({
      baseUrl: 'https://corrobore:8080',
      token: 'secret',
      tokenFile: undefined,
      timeoutMs: 30000,
    });
    expect(() => parseCorroboreConfig({
      DATABASE_ENGINE: 'corrobore',
      CORROBORE__URL: 'https://corrobore:8080',
      CORROBORE__AUTH_TOKEN: 'secret',
      ELASTICSEARCH__URL: 'http://elasticsearch:9200',
    })).toThrow(/Elastic-free mode rejects ELASTICSEARCH__URL/);
  });

  it('propagates OpenCTI authorization facts without transport credentials', () => {
    const access = accessContextFromUser({
      internal_id: 'user--1',
      roles: [{ name: 'Analyst' }],
      capabilities: [],
      groups: [{ internal_id: 'group--1' }],
      organizations: [{ internal_id: 'organization--1' }],
      allowed_marking: [{ internal_id: 'marking--1' }],
    });
    expect(access).toEqual({
      subject_id: 'user--1',
      organization_ids: ['organization--1'],
      marking_ids: ['marking--1'],
      tenant_id: null,
      roles: ['Analyst'],
      attributes: { group_ids: '["group--1"]' },
    });
    expect(JSON.stringify(access)).not.toContain('api_token');
    expect(accessContextFromUser({
      internal_id: 'system--1', roles: [{ name: 'Administrator' }], capabilities: [{ name: 'BYPASS' }],
    }).roles).toEqual(['Administrator', 'system']);
  });

  it('translates nested OpenCTI filters into the typed provider predicate', () => {
    const predicate = filterGroupToPredicate({
      mode: FilterMode.And,
      filters: [{ key: ['entity_type'], operator: FilterOperator.Eq, values: ['Indicator'] }],
      filterGroups: [{
        mode: FilterMode.Or,
        filters: [
          { key: ['confidence'], operator: FilterOperator.Gte, values: [75] },
          { key: ['revoked'], operator: FilterOperator.Eq, values: [false] },
        ],
        filterGroups: [],
      }],
    });
    expect(predicate).toEqual({
      operator: 'and',
      arguments: [
        { operator: 'condition', arguments: { field: 'entity_type', operator: 'equal', value: 'Indicator' } },
        { operator: 'or', arguments: [
          { operator: 'condition', arguments: { field: 'confidence', operator: 'greater_than_or_equal', value: 75 } },
          { operator: 'condition', arguments: { field: 'revoked', operator: 'equal', value: false } },
        ] },
      ],
    });
  });

  it('preserves nested-object filter scope and ignores empty filter groups', () => {
    expect(filterGroupToPredicate({
      mode: FilterMode.And,
      filters: [{
        key: ['connections'],
        values: [],
        nested: [
          { key: ['internal_id'], values: ['identity--1'], operator: FilterOperator.Eq },
          { key: ['role'], values: ['*_from'], operator: FilterOperator.Wildcard },
        ],
      }],
      filterGroups: [],
    })).toEqual({
      operator: 'nested',
      arguments: {
        path: 'connections',
        predicate: {
          operator: 'and',
          arguments: [
            { operator: 'condition', arguments: { field: 'internal_id', operator: 'equal', value: 'identity--1' } },
            { operator: 'condition', arguments: { field: 'role', operator: 'wildcard', value: '*_from' } },
          ],
        },
      },
    });
    expect(filterGroupToPredicate({ mode: FilterMode.And, filters: [], filterGroups: [] })).toBeNull();
  });

  it('routes typed reads and writes and unwraps the stable response envelope', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ ready: true }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ opencti_mode: 'elastic_free' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(success('initialized', {
        capabilities: [
          'initialize', 'get_by_id', 'list', 'paginate', 'search', 'count', 'aggregate',
          'create', 'update', 'delete', 'bulk', 'merge',
        ].map((operation) => ({ operation, status: { status: 'supported' } })),
      })), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(success('record', {
        id: 'indicator--1', kind: 'Indicator', revision: 3, body: { internal_id: 'indicator--1', name: 'APT' },
      })), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(success('write', {
        id: 'indicator--1', revision: 4,
      })), { status: 200 }));
    const client = new CorroboreProviderClient({
      baseUrl: 'https://corrobore:8080', token: 'secret', timeoutMs: 1000,
    }, fetch);

    await client.initialize();
    const initializeBody = JSON.parse(fetch.mock.calls[2][1]?.body as string);
    expect(initializeBody.request.context.access).toEqual({
      subject_id: 'system',
      organization_ids: [],
      marking_ids: [],
      tenant_id: null,
      roles: ['system'],
      attributes: {},
    });
    await expect(client.read({ operation: 'get_by_id', request: { id: 'indicator--1' } }, {
      requestId: 'request--1', correlationId: 'correlation--1', access: { subject_id: 'system', roles: ['system'] },
    })).resolves.toEqual({
      response: 'record',
      data: { id: 'indicator--1', kind: 'Indicator', revision: 3, body: { internal_id: 'indicator--1', name: 'APT' } },
    });
    await expect(client.write({ operation: 'update', request: {
      id: 'indicator--1', expected_revision: 3, patch: { name: 'APT 2' },
    } }, {
      requestId: 'request--2', correlationId: 'correlation--1', idempotencyKey: 'update--1',
      access: { subject_id: 'system', roles: ['system'] },
    })).resolves.toEqual({ response: 'write', data: { id: 'indicator--1', revision: 4 } });

    expect(fetch.mock.calls.map(([url]) => new URL(url as string).pathname)).toEqual([
      '/health/ready', '/version', '/v1/opencti/reads', '/v1/opencti/reads', '/v1/opencti/writes',
    ]);
    const readBody = JSON.parse(fetch.mock.calls[3][1]?.body as string);
    expect(readBody.request.operation).toEqual({ operation: 'get_by_id', request: { id: 'indicator--1' } });
    expect(readBody.request.context.access).toEqual({ subject_id: 'system', roles: ['system'] });
    expect(fetch.mock.calls[3][1]?.headers).toMatchObject({ authorization: 'Bearer secret' });
  });

  it('fails closed on stable provider errors and builds opaque cursor connections', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      contract_version: { major: 1, minor: 0 },
      correlation_id: 'correlation--1',
      outcome: { status: 'failure', error: { code: 'unauthorized', message: 'denied', retryable: false } },
    }), { status: 200 }));
    const client = new CorroboreProviderClient({
      baseUrl: 'https://corrobore:8080', token: 'secret', timeoutMs: 1000,
    }, fetch);
    await expect(client.read({ operation: 'get_by_id', request: { id: 'indicator--1' } }, {
      requestId: 'request--1', correlationId: 'correlation--1', access: { subject_id: 'user--1' },
    })).rejects.toMatchObject({ code: 'unauthorized', retryable: false });

    expect(recordPageToConnection({
      records: [{ id: 'indicator--1', kind: 'Indicator', revision: 1, body: { internal_id: 'indicator--1' } }],
      next_token: 'kde1.opaque.token',
      total_count: 7,
    })).toEqual({
      edges: [{ cursor: 'kde1.opaque.token', node: { internal_id: 'indicator--1' } }],
      pageInfo: {
        startCursor: 'kde1.opaque.token', endCursor: 'kde1.opaque.token', hasNextPage: true, hasPreviousPage: false, globalCount: 7,
      },
    });
  });

  it('routes file extraction lifecycle commands to the durable Corrobore queue', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true, result: 'enqueued', job_id: 'job--1' }), { status: 202 }));
    const client = new CorroboreProviderClient({
      baseUrl: 'https://corrobore:8080', token: 'secret', timeoutMs: 1000,
    }, fetch);
    await expect(client.fileCommand({ operation: 'enqueue', descriptor: {
      file_id: 'import/test.txt', source_object_id: 'indicator--1', blob_key: 'import/test.txt',
      name: 'test.txt', mime_type: 'text/plain', content_hash: 'a'.repeat(64), version: 1,
      access: { marking_ids: [], organization_ids: [] },
    } })).resolves.toMatchObject({ ok: true, result: 'enqueued' });
    expect(new URL(fetch.mock.calls[0][0] as string).pathname).toBe('/v1/opencti/files');
  });

  it('retries bounded Corrobore rate limits within the request timeout', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: 'rate limited' }), {
        status: 429,
        headers: { 'retry-after': '0' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    const client = new CorroboreProviderClient({
      baseUrl: 'https://corrobore:8080', token: 'secret', timeoutMs: 1000,
    }, fetch);

    await expect(client.fileCommand({ operation: 'delete', file_id: 'import/test.txt' }))
      .resolves.toEqual({ ok: true });
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
