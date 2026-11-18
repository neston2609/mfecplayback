const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function collectWrapUpCodeIds(conversation: any): string[] {
  const ids = new Set<string>();
  for (const participant of Array.isArray(conversation?.participants) ? conversation.participants : []) {
    for (const session of Array.isArray(participant?.sessions) ? participant.sessions : []) {
      for (const segment of Array.isArray(session?.segments) ? session.segments : []) {
        const id = typeof segment?.wrapUpCodeId === 'string'
          ? segment.wrapUpCodeId
          : typeof segment?.wrapUpCode === 'string' && UUID.test(segment.wrapUpCode) ? segment.wrapUpCode : undefined;
        if (id && id.length <= 128) ids.add(id);
      }
    }
  }
  return [...ids];
}

export function collectAfterCallNotes(conversation: any): { agent: string; note: string; startTime?: string; endTime?: string }[] {
  const notes: { agent: string; note: string; startTime?: string; endTime?: string }[] = [];
  for (const participant of Array.isArray(conversation?.participants) ? conversation.participants : []) {
    for (const session of Array.isArray(participant?.sessions) ? participant.sessions : []) {
      for (const segment of Array.isArray(session?.segments) ? session.segments : []) {
        if (typeof segment?.wrapUpNote !== 'string' || !segment.wrapUpNote.trim()) continue;
        notes.push({
          agent: typeof participant?.participantName === 'string' ? participant.participantName : typeof participant?.userId === 'string' ? participant.userId : 'Agent',
          note: segment.wrapUpNote.trim(),
          ...(typeof segment.segmentStart === 'string' ? { startTime: segment.segmentStart } : {}),
          ...(typeof segment.segmentEnd === 'string' ? { endTime: segment.segmentEnd } : {}),
        });
      }
    }
  }
  return notes;
}

/** Attach a display name to analytics segments while avoiding UUIDs as user-facing values. */
export function withWrapUpCodeNames(conversation: any, names: Record<string, string>): any {
  if (Array.isArray(conversation)) return conversation.map(item => withWrapUpCodeNames(item, names));
  if (!conversation || typeof conversation !== 'object') return conversation;
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(conversation)) result[key] = withWrapUpCodeNames(value, names);
  if (Array.isArray(conversation.segments)) {
    result.segments = conversation.segments.map((segment: any) => {
      const copy = { ...segment };
      const id = typeof segment?.wrapUpCodeId === 'string'
        ? segment.wrapUpCodeId
        : typeof segment?.wrapUpCode === 'string' && UUID.test(segment.wrapUpCode) ? segment.wrapUpCode : undefined;
      if (id) copy.wrapUpCodeName = names[id] || segment.wrapUpCodeName || 'Wrap-up code unavailable';
      else if (typeof segment?.wrapUpCode === 'string') copy.wrapUpCodeName = segment.wrapUpCode;
      else if (typeof segment?.wrapUpCode?.name === 'string') copy.wrapUpCodeName = segment.wrapUpCode.name;
      return copy;
    });
  }
  return result;
}

export function isWrapUpCodeId(value: unknown): value is string {
  return typeof value === 'string' && UUID.test(value);
}
