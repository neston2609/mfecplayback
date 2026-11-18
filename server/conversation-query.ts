type AnalyticsQueryClient = {
  post<T>(path: string, body: unknown): Promise<T>;
};

export const ANALYTICS_CONVERSATION_PAGE_SIZE = 100;
export const MAX_ANALYTICS_CONVERSATIONS = 1000;
const MAX_CONVERSATION_PAGES = MAX_ANALYTICS_CONVERSATIONS / ANALYTICS_CONVERSATION_PAGE_SIZE;

export async function queryAllConversations(
  client: AnalyticsQueryClient,
  interval: string,
  filters: Record<string, unknown> = {},
  maxConversations = MAX_ANALYTICS_CONVERSATIONS,
) {
  const conversations = new Map<string, any>();
  const queryConversationIds = new Set<string>();
  let totalHits: number | null = null;
  let partial = false;
  const pageLimit = Math.max(1, Math.ceil(maxConversations / ANALYTICS_CONVERSATION_PAGE_SIZE));

  for (let pageNumber = 1; pageNumber <= Math.min(MAX_CONVERSATION_PAGES, pageLimit); pageNumber++) {
    // Keep pageSize stable across Analytics pages because changing it changes
    // the page offsets and can create overlaps or gaps.
    const pageSize = ANALYTICS_CONVERSATION_PAGE_SIZE;
    const response = await client.post<{
      conversations?: any[];
      totalHits?: number;
      totalCount?: number;
    }>('/api/v2/analytics/conversations/details/query', {
      interval,
      paging: { pageSize, pageNumber },
      order: 'desc',
      orderBy: 'conversationStart',
      ...filters,
    });

    const page = Array.isArray(response?.conversations) ? response.conversations : [];
    for (const conversation of page) {
      if (conversation?.conversationId) {
        if (!queryConversationIds.has(conversation.conversationId) && queryConversationIds.size >= maxConversations) {
          partial = true;
          continue;
        }
        queryConversationIds.add(conversation.conversationId);
        if (!conversations.has(conversation.conversationId)) conversations.set(conversation.conversationId, conversation);
      }
    }

    totalHits = response?.totalHits ?? response?.totalCount ?? totalHits;
    if (partial || page.length === 0 || (totalHits !== null && queryConversationIds.size >= totalHits)) break;
    if (page.length < pageSize) break;

    if (pageNumber === Math.min(MAX_CONVERSATION_PAGES, pageLimit)) {
      // Never present a capped result as complete when Genesys may have more pages.
      partial = totalHits === null || totalHits > maxConversations || queryConversationIds.size < totalHits;
    }
  }

  if (totalHits !== null && queryConversationIds.size < totalHits) partial = true;
  return { conversations: [...conversations.values()], totalHits, partial };
}
