export interface GenesysArtifactClient {
  get(path: string): Promise<unknown>;
  post(path: string, body: unknown): Promise<unknown>;
}

export function analyticsConversationDetailsPath(conversationId: string): string {
  return `/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`;
}

export function avaConversationSummaryPath(conversationId: string): string {
  return `/api/v2/conversations/${encodeURIComponent(conversationId)}/summaries`;
}

export function aiConversationSummaryPath(conversationId: string): string {
  return `/api/v2/speechandtextanalytics/conversations/${encodeURIComponent(conversationId)}/summaries`;
}

export function transcriptSearchPath(): string {
  return '/api/v2/speechandtextanalytics/transcripts/search';
}

export function transcriptSearchRequest(conversationId: string) {
  return {
    pageSize: 100,
    pageNumber: 1,
    types: ['transcripts'],
    returnFields: ['conversationId', 'communicationId'],
    query: [{ type: 'EXACT', fields: ['conversationId'], value: conversationId }],
  };
}

export function transcriptSearchCommunicationIds(response: unknown, conversationId: string): string[] {
  const communicationIds = new Set<string>();
  const visited = new Set<object>();
  const candidates: unknown[] = [];
  let candidateCount = 0;

  function visit(value: unknown) {
    if (!value || typeof value !== 'object' || visited.has(value)) return;
    if (++candidateCount > 10000) return;
    visited.add(value);
    if (Array.isArray(value)) {
      for (const item of value) visit(item);
      return;
    }

    const record = value as Record<string, unknown>;
    if (Object.hasOwn(record, 'conversationId') || Object.hasOwn(record, 'communicationId')) candidates.push(record);

    for (const item of Object.values(record)) visit(item);
  }

  visit(response);
  const matches = candidates.filter(item => {
    const record = item as Record<string, unknown>;
    return typeof record.conversationId === 'string' && record.conversationId === conversationId;
  });
  const hasConversationIds = candidates.some(item => typeof (item as Record<string, unknown>).conversationId === 'string');
  for (const item of matches.length || hasConversationIds ? matches : candidates) {
    const communicationId = (item as Record<string, unknown>).communicationId;
    if (typeof communicationId === 'string' && communicationId.trim() && communicationId.length <= 128) communicationIds.add(communicationId);
  }
  return [...communicationIds];
}

function isSummaryUnavailable(error: unknown): boolean {
  const status = (error as { status?: unknown } | null)?.status;
  return status === 403 || status === 404 || status === 409;
}

export async function fetchConversationSummaryArtifacts(client: GenesysArtifactClient, conversationId: string) {
  const [avaResult, aiResult] = await Promise.allSettled([
    client.get(avaConversationSummaryPath(conversationId)),
    client.get(aiConversationSummaryPath(conversationId)),
  ]);

  for (const result of [avaResult, aiResult]) {
    if (result.status === 'rejected' && !isSummaryUnavailable(result.reason)) throw result.reason;
  }

  const avaSummary = avaResult.status === 'fulfilled' ? avaResult.value ?? null : null;
  const aiSummary = aiResult.status === 'fulfilled' ? aiResult.value ?? null : null;
  if (avaSummary === null && aiSummary === null) {
    const error = new Error('Genesys has no conversation summary available for this conversation.') as Error & { status: number };
    error.status = [avaResult, aiResult].some(result => result.status === 'rejected' && (result.reason as { status?: number })?.status === 403) ? 403 : 404;
    throw error;
  }
  return { avaSummary, aiSummary };
}
