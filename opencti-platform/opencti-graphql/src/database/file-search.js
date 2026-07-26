/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import * as R from 'ramda';
import { createHash } from 'node:crypto';
import { now } from '../utils/format';
import { buildRefRelationKey } from '../schema/general';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { buildPagination, cursorToOffset, INDEX_FILES, READ_DATA_INDICES_WITHOUT_INTERNAL, READ_INDEX_FILES } from './utils';
import { DatabaseError } from '../config/errors';
import { logApp } from '../config/conf';
import { buildDataRestrictions, elFindByIds, elIndex, elRawCount, elRawDeleteByQuery, elRawSearch, elRawUpdateByQuery, ES_MINIMUM_FIXED_PAGINATION } from './engine';
import { corroboreFileCommand, corroboreRead, isCorroboreProviderConfigured } from './providers/corrobore/corrobore-provider';

const relationIds = (entity, field) => (entity?.[field] ?? [])
  .map((value) => value?.internal_id ?? value?.id ?? value)
  .filter((value) => typeof value === 'string' && value.length > 0);

const corroboreFileAccess = (entity) => ({
  marking_ids: relationIds(entity, RELATION_OBJECT_MARKING),
  organization_ids: relationIds(entity, RELATION_GRANTED_TO),
  authorized_members: entity?.authorized_members ?? [],
  tenant_ids: entity?.tenant_ids ?? [],
  creator_ids: entity?.creator_id ? [entity.creator_id].flat() : [],
  owner_ids: entity?.objectOrganization?.map((value) => value.internal_id ?? value.id) ?? [],
  sharing_policy: entity?.sharing_policy ?? null,
  authorized_authorities: entity?.authorized_authorities ?? [],
});

const fileDigest = (file) => {
  const declared = file.hashes?.SHA256 ?? file.hashes?.sha256 ?? file.sha256;
  if (typeof declared === 'string' && /^[a-f0-9]{64}$/i.test(declared)) return declared.toLowerCase();
  const content = typeof file.content === 'string' ? Buffer.from(file.content, 'base64') : Buffer.alloc(0);
  return createHash('sha256').update(content).digest('hex');
};

const buildIndexFileBody = (documentId, file, entity = null) => {
  const documentBody = {
    internal_id: documentId,
    indexed_at: now(),
    file_id: file.id,
    file_data: file.content,
    name: file.name,
    uploaded_at: file.uploaded_at,
  };
  if (entity) {
    documentBody.entity_id = entity.internal_id;
    // index entity markings & organization restrictions
    documentBody.entity_type = entity.entity_type;
    documentBody.parent_types = entity.parent_types;
    documentBody[buildRefRelationKey(RELATION_OBJECT_MARKING)] = entity[RELATION_OBJECT_MARKING] ?? [];
    documentBody[buildRefRelationKey(RELATION_GRANTED_TO)] = entity[RELATION_GRANTED_TO] ?? [];
    // index entity authorized_members & authorized_authorities => not yet
    // documentBody.authorized_members = entity.authorized_members ?? [];
    // documentBody.authorized_authorities = entity.authorized_authorities ?? [];
  }
  return documentBody;
};

export const elIndexFiles = async (context, user, files) => {
  if (!files || files.length === 0) {
    return;
  }
  const entityIds = files.filter((file) => !!file.entity_id).map((file) => file.entity_id);
  const opts = { indices: READ_DATA_INDICES_WITHOUT_INTERNAL, toMap: true };
  const entitiesMap = await elFindByIds(context, user, entityIds, opts);
  if (isCorroboreProviderConfigured()) {
    for (const file of files) {
      const entity = file.entity_id ? entitiesMap[file.entity_id] : null;
      await corroboreFileCommand({
        operation: 'enqueue',
        descriptor: {
          file_id: file.file_id ?? file.id,
          source_object_id: file.entity_id ?? file.source_object_id ?? 'opencti--unattached-file',
          blob_key: file.file_id ?? file.id,
          name: file.name,
          mime_type: file.mime_type ?? file.mimetype ?? file.content_type ?? 'application/octet-stream',
          content_hash: fileDigest(file),
          version: Number(file.version ?? 1),
          access: corroboreFileAccess(entity),
        },
      });
    }
    return;
  }
  for (let index = 0; index < files.length; index += 1) {
    const file = files[index];
    const { internal_id, file_data, file_id, entity_id } = file;
    if (internal_id && file_id && file_data) {
      const entity = entity_id ? entitiesMap[entity_id] : null;
      const fileObject = {
        id: file_id,
        content: file_data,
        name: file.name,
        uploaded_at: file.uploaded_at,
      };
      const documentBody = buildIndexFileBody(internal_id, fileObject, entity);
      try {
        await elIndex(INDEX_FILES, documentBody, { pipeline: 'attachment' });
      } catch (err) {
        // catch & log error
        logApp.error('Error on file indexing', { cause: err, file_id });
        // try to index without file content
        const documentWithoutFileData = R.dissoc('file_data', documentBody);
        await elIndex(INDEX_FILES, documentWithoutFileData).catch((e) => {
          logApp.error('Error in fallback file indexing', { message: e.message, cause: e, file_id });
        });
      }
    }
  }
};

export const elUpdateFilesWithEntityRestrictions = async (entity) => {
  if (!entity) {
    return null;
  }
  const changes = {
    [buildRefRelationKey(RELATION_OBJECT_MARKING)]: entity[RELATION_OBJECT_MARKING] ?? [],
    [buildRefRelationKey(RELATION_GRANTED_TO)]: entity[RELATION_GRANTED_TO] ?? [],
  };
  const source = 'for (change in params.changes.entrySet()) { ctx._source[change.getKey()] = change.getValue() }';
  return elRawUpdateByQuery({
    index: READ_INDEX_FILES,
    refresh: true,
    conflicts: 'proceed',
    body: {
      script: { source, params: { changes } },
      query: {
        term: {
          'entity_id.keyword': entity.internal_id,
        },
      },
    },
  }).catch((err) => {
    throw DatabaseError('Files entity restrictions indexing fail', { cause: err, entityId: entity.internal_id });
  });
};

export const elUpdateRemovedFiles = async (entity, removed = true) => {
  if (!entity) {
    return null;
  }
  const params = { removed };
  const source = 'ctx._source["removed"] = params.removed;';
  return elRawUpdateByQuery({
    index: READ_INDEX_FILES,
    refresh: true,
    conflicts: 'proceed',
    body: {
      script: { source, params },
      query: {
        term: {
          'entity_id.keyword': entity.internal_id,
        },
      },
    },
  }).catch((err) => {
    throw DatabaseError('Files entity removed update fail', { cause: err, entityId: entity.internal_id });
  });
};

const buildFilesSearchResult = (data, first, searchAfter, connectionFormat = true, includeContent = false) => {
  const convertedHits = data.hits.hits.map((hit) => {
    const elementData = hit._source;
    const searchOccurrences = (hit.highlight && hit.highlight['attachment.content'])
      ? hit.highlight['attachment.content'].length : 0;
    const element = {
      _index: hit._index,
      id: elementData.internal_id,
      internal_id: elementData.internal_id,
      name: elementData.name,
      indexed_at: elementData.indexed_at,
      uploaded_at: elementData.uploaded_at,
      entity_id: elementData.entity_id,
      file_id: elementData.file_id,
      searchOccurrences,
      sort: hit.sort,
    };
    if (includeContent) {
      return { ...element, content: elementData.attachment.content };
    }
    return element;
  });
  if (connectionFormat) {
    const nodeHits = R.map((n) => ({ node: n, sort: n.sort }), convertedHits);
    return buildPagination(first, searchAfter, nodeHits, data.hits.total.value);
  }
  return convertedHits;
};
const decodeSearch = (search) => {
  let decodedSearch;
  try {
    decodedSearch = decodeURIComponent(search).trim();
  } catch (_e) {
    decodedSearch = search.trim();
  }
  return decodedSearch;
};
const elBuildSearchFilesQueryBody = async (context, user, options = {}) => {
  const { search = null, fileIds = [], entityIds = [] } = options; // search options
  const { includeAuthorities = false, excludeRemoved = true } = options;
  const dataRestrictions = await buildDataRestrictions(context, user, { includeAuthorities });
  const must = [...dataRestrictions.must];
  const mustNot = [...dataRestrictions.must_not];
  if (search) {
    const decodedSearch = decodeSearch(search);
    const fullTextSearch = {
      simple_query_string: {
        query: decodedSearch,
        fields: ['attachment.content', 'attachment.title^2'],
      },
    };
    must.push(fullTextSearch);
  }
  if (fileIds?.length > 0) {
    must.push({ terms: { 'file_id.keyword': fileIds } });
  }
  if (entityIds?.length > 0) {
    must.push({ terms: { 'entity_id.keyword': entityIds } });
  }
  // exclude removed files (logical deletion)
  if (excludeRemoved) {
    const excludeRemovedQuery = {
      bool: {
        should: [
          { term: { removed: { value: false } } },
          { bool: { must_not: [{ exists: { field: 'removed' } }] } },
        ],
      },
    };
    must.push(excludeRemovedQuery);
  }
  return {
    query: {
      bool: {
        must,
        must_not: mustNot,
      },
    },
  };
};
export const elSearchFiles = async (context, user, options = {}) => {
  const { search = null, first = ES_MINIMUM_FIXED_PAGINATION, after, connectionFormat = true, includeContent = false, orderBy = null, orderMode = 'asc' } = options;
  const { fields = [], excludeFields = ['attachment.content'], highlight = true } = options; // results format options
  if (isCorroboreProviderConfigured()) {
    const { fileIds = [], entityIds = [], mimeTypes = [] } = options;
    if (fileIds.length > 0) throw DatabaseError('Corrobore file search does not accept fileIds; use entityIds or full-text criteria');
    const response = await corroboreRead({ operation: 'search', request: {
      expression: {
        text: decodeSearch(search ?? ''),
        content: true,
        mime_types: mimeTypes,
        owner_ids: [],
        source_object_ids: entityIds,
        cursor: after ?? null,
      },
      limit: first,
    } }, context, user);
    if (response.response !== 'search') throw DatabaseError(`Corrobore returned ${response.response} for file search`);
    const hits = response.data?.hits ?? [];
    const edges = hits.map((hit) => ({
      cursor: response.data?.next_cursor ?? '',
      node: {
        _index: INDEX_FILES,
        id: hit.id,
        internal_id: hit.id,
        file_id: hit.id,
        entity_id: hit.metadata?.source_object_id,
        name: hit.metadata?.name ?? hit.id,
        searchOccurrences: hit.highlights?.length ?? 0,
        ...(includeContent ? { content: hit.snippet ?? '' } : {}),
      },
    }));
    if (!connectionFormat) return edges.map((edge) => edge.node);
    return {
      edges,
      pageInfo: {
        startCursor: edges[0]?.cursor ?? '',
        endCursor: edges.at(-1)?.cursor ?? '',
        hasNextPage: response.data?.next_cursor != null,
        hasPreviousPage: after != null,
        globalCount: response.data?.total ?? edges.length,
      },
    };
  }
  const searchAfter = after ? cursorToOffset(after) : undefined;
  const body = await elBuildSearchFilesQueryBody(context, user, options);
  body.size = first;
  const sort = [];
  if (!orderBy) {
    // order by last indexed date by default
    if (search) {
      sort.push({ _score: 'desc' });
    }
    sort.push({ indexed_at: 'desc' });
    // add internal_id sort since indexed_at is not unique
    sort.push({ 'internal_id.keyword': 'desc' });
  } else {
    sort.push({ [orderBy]: orderMode });
  }
  body.sort = sort;
  if (searchAfter) {
    body.search_after = searchAfter;
  }
  if (highlight) {
    body.highlight = {
      fields: {
        'attachment.content': { type: 'unified', boundary_scanner: 'word', number_of_fragments: 100 },
      },
    };
  }
  const sourceIncludes = (fields?.length > 0) ? fields : [];
  const sourceExcludes = (excludeFields?.length > 0) ? excludeFields : [];
  const query = {
    index: INDEX_FILES,
    track_total_hits: true,
    _source: { includes: sourceIncludes, excludes: sourceExcludes },
    body,
  };
  logApp.debug('[SEARCH] search files', { query });
  return elRawSearch(context, user, null, query)
    .then((data) => {
      return buildFilesSearchResult(data, first, body.search_after, connectionFormat, includeContent);
    })
    .catch((err) => {
      throw DatabaseError('Files search pagination fail', { cause: err, query });
    });
};

export const elCountFiles = async (context, user, options = {}) => {
  if (isCorroboreProviderConfigured()) {
    const result = await elSearchFiles(context, user, { ...options, first: 1000, connectionFormat: true });
    return result.pageInfo.globalCount;
  }
  const body = await elBuildSearchFilesQueryBody(context, user, options);
  const query = { index: INDEX_FILES, body };
  logApp.debug('elCountFiles', { query });
  return elRawCount(query);
};

export const elDeleteFilesByIds = async (fileIds) => {
  if (!fileIds) {
    return;
  }
  if (isCorroboreProviderConfigured()) {
    await corroboreFileCommand({ operation: 'delete', file_ids: fileIds });
    return;
  }
  const query = {
    terms: { 'file_id.keyword': fileIds },
  };
  await elRawDeleteByQuery({
    index: READ_INDEX_FILES,
    refresh: true,
    body: { query },
  }).catch((err) => {
    throw DatabaseError('Error deleting files by ids', { cause: err });
  });
};

export const elDeleteAllFiles = async () => {
  if (isCorroboreProviderConfigured()) {
    throw DatabaseError('Corrobore requires explicit file identifiers for deletion');
  }
  await elRawDeleteByQuery({
    index: READ_INDEX_FILES,
    refresh: true,
    body: {
      query: {
        match_all: {},
      },
    },
  }).catch((err) => {
    throw DatabaseError('Error deleting all files ', { cause: err });
  });
};
