const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const GENERIC_AGENT_NAMES = new Set(['agent', 'user', 'unknown', 'ivr flow', 'flow unavailable']);

function readableName(value: unknown): string {
  if (typeof value !== 'string') return '';
  const name = value.trim();
  return name && !UUID.test(name) ? name : '';
}

export function readablePhone(value: unknown): string {
  if (typeof value !== 'string') return '';
  const phone = value.trim();
  if (!phone || /^(?:sips?:|[^\s@]+@)/i.test(phone) || phone.includes('@')) return '';
  return phone.replace(/^tel:/i, '');
}

export type ParticipantLine = {
  purpose: string;
  displayPurpose: string;
  displayName: string;
  displayText: string;
};

function displayPurpose(purpose: string): string {
  const normalized = purpose.trim().toLowerCase();
  if (normalized === 'customer') return 'Customer';
  if (normalized === 'agent') return 'Agent';
  if (normalized === 'botflow') return 'Botflow';
  if (normalized === 'ivr') return 'IVR';
  if (normalized === 'acd') return 'ACD';
  return normalized ? normalized[0].toUpperCase() + normalized.slice(1) : 'Participant';
}

function participantPhone(participant: any, field: 'ani' | 'dnis'): string {
  for (const session of participant?.sessions || []) {
    const phone = readablePhone(session?.[field]);
    if (phone) return phone;
  }
  return '—';
}

function participantFlowName(participant: any): string {
  for (const session of participant?.sessions || []) {
    const flowName = readableName(session?.flow?.flowName) || readableName(session?.flowName);
    if (flowName) return flowName;
  }
  return '';
}

function participantUserId(participant: any): string {
  if (typeof participant?.userId === 'string' && participant.userId) return participant.userId;
  for (const session of Array.isArray(participant?.sessions) ? participant.sessions : []) {
    if (typeof session?.userId === 'string' && session.userId) return session.userId;
    for (const segment of Array.isArray(session?.segments) ? session.segments : []) {
      if (typeof segment?.userId === 'string' && segment.userId) return segment.userId;
    }
  }
  return '';
}

export function participantLines(participants: any[], userNames: Record<string, string> = {}): ParticipantLine[] {
  return participants.map(participant => {
    const purpose = typeof participant?.purpose === 'string' ? participant.purpose : '';
    const normalized = purpose.toLowerCase();
    const participantName = readableName(participant?.participantName);
    const userId = participantUserId(participant);
    let displayName = participantName || '—';

    if (normalized === 'customer') {
      displayName = `${participantPhone(participant, 'ani')} -> ${participantPhone(participant, 'dnis')}`;
    } else if (normalized === 'agent') {
      displayName = readableName(userNames[userId]) || participantName || 'Name unavailable';
    } else if (normalized === 'user') {
      const participantId=typeof participant?.participantId==='string'?participant.participantId:'';
      displayName=readableName(userNames[participantId])||participantName||'User';
    } else if (normalized === 'botflow' || normalized === 'ivr' || normalized === 'flow') {
      displayName = participantFlowName(participant) || participantName || 'Flow unavailable';
    }

    const label = displayPurpose(purpose);
    return { purpose, displayPurpose: label, displayName, displayText: `${label} : ${displayName}` };
  });
}

export function withParticipantLines(conversation: any, userNames: Record<string, string> = {}) {
  const lines = participantLines(conversation?.participants || [], userNames);
  return {
    ...conversation,
    participants: (conversation?.participants || []).map((participant: any, index: number) => ({
      ...participant,
      displayPurpose: lines[index].displayPurpose,
      displayName: lines[index].displayName,
      displayText: lines[index].displayText,
    })),
  };
}

export function collectQueueIds(conversation: any): string[] {
  const ids = new Set<string>();
  for (const participant of Array.isArray(conversation?.participants) ? conversation.participants : []) {
    const participantQueueId = typeof participant?.queueId === 'string' ? participant.queueId : '';
    if (participantQueueId && UUID.test(participantQueueId)) ids.add(participantQueueId);
    for (const session of Array.isArray(participant?.sessions) ? participant.sessions : []) {
      const sessionQueueId = typeof session?.queueId === 'string' ? session.queueId : '';
      if (sessionQueueId && UUID.test(sessionQueueId)) ids.add(sessionQueueId);
      for (const segment of Array.isArray(session?.segments) ? session.segments : []) {
        const segmentQueueId = typeof segment?.queueId === 'string' ? segment.queueId : '';
        if (segmentQueueId && UUID.test(segmentQueueId)) ids.add(segmentQueueId);
      }
    }
  }
  return [...ids];
}

export function conversationQueueNames(conversation: any, resolvedNames: Record<string, string> = {}): string[] {
  const names = new Set<string>();
  for (const [id, value] of Object.entries(resolvedNames)) {
    if (!UUID.test(id)) continue;
    const name = readableName(value);
    if (name) names.add(name);
  }
  for (const participant of Array.isArray(conversation?.participants) ? conversation.participants : []) {
    const purpose = String(participant?.purpose || '').toLowerCase();
    if (purpose === 'acd') {
      const name = readableName(participant?.participantName);
      if (name && !['acd', 'queue'].includes(name.toLowerCase())) names.add(name);
    }
    for (const session of Array.isArray(participant?.sessions) ? participant.sessions : []) {
      const sessionName = readableName(session?.queueName);
      if (sessionName) names.add(sessionName);
      for (const segment of Array.isArray(session?.segments) ? session.segments : []) {
        const segmentName = readableName(segment?.queueName);
        if (segmentName) names.add(segmentName);
      }
    }
  }
  return [...names];
}

export function conversationWrapUpCodeNames(conversation: any): string[] {
  const names = new Set<string>();
  for (const participant of Array.isArray(conversation?.participants) ? conversation.participants : []) {
    for (const session of Array.isArray(participant?.sessions) ? participant.sessions : []) {
      for (const segment of Array.isArray(session?.segments) ? session.segments : []) {
        const candidates = [segment?.wrapUpCodeName, segment?.wrapUpCode?.name, segment?.wrapUpCode];
        const name = candidates.map(readableName).find(value => value && value !== 'Wrap-up code unavailable');
        if (name) names.add(name);
      }
    }
  }
  return [...names];
}

export function archivedConversationDisplay(conversation: any, recordingDurationMs?: number | null) {
  const summary = conversation?.conversation && typeof conversation.conversation === 'object'
    ? conversation.conversation
    : conversation || {};
  const safeNames = (value: unknown) => (Array.isArray(value) ? value : [])
    .map(readableName)
    .filter(name => Boolean(name) && !GENERIC_AGENT_NAMES.has(name.toLowerCase()));
  let agents = safeNames(summary.agents);
  if (!agents.length && Array.isArray(summary.participants)) {
    agents = safeNames(summary.participants
      .filter((participant: any) => String(participant?.purpose || '').toLowerCase() === 'agent')
      .map((participant: any) => participant?.displayName || participant?.participantName));
  }
  let flows = safeNames(summary.flows);
  if (!flows.length && Array.isArray(summary.participants)) {
    flows = safeNames(summary.participants
      .filter((participant: any) => ['ivr', 'flow', 'botflow'].includes(String(participant?.purpose || '').toLowerCase()))
      .map((participant: any) => participant?.displayName || participant?.participantName));
  }
  const summaryDuration = summary.durationSeconds;
  const recordingDuration = recordingDurationMs;
  const durationSeconds = summaryDuration !== null && summaryDuration !== undefined && Number.isFinite(Number(summaryDuration)) && Number(summaryDuration) >= 0
    ? Math.round(Number(summaryDuration))
    : recordingDuration !== null && recordingDuration !== undefined && Number.isFinite(Number(recordingDuration)) && Number(recordingDuration) >= 0
      ? Math.round(Number(recordingDuration) / 1000)
      : null;
  return {
    agents: agents.length ? [...new Set(agents)] : [],
    flows: flows.length ? [...new Set(flows)] : [],
    queues: [...new Set(safeNames(summary.queues))],
    interactionType: readableName(summary.interactionType) || 'Unknown',
    direction: String(summary.direction || '').toLowerCase(),
    callbackNumber: readablePhone(summary.callbackNumber),
    ani: readablePhone(summary.ani),
    dnis: readablePhone(summary.dnis),
    durationSeconds,
  };
}

function firstPhone(participants: any[], field: 'ani' | 'dnis'): string {
  const ordered = [...participants].sort((a, b) => Number(b?.purpose === 'customer') - Number(a?.purpose === 'customer'));
  for (const participant of ordered) {
    for (const session of participant?.sessions || []) {
      const phone = readablePhone(session?.[field]);
      if (phone) return phone;
    }
  }
  return '';
}

function firstCallbackNumber(participants: any[]): string {
  const ordered=[...participants].sort((a,b)=>Number(b?.purpose==='customer')-Number(a?.purpose==='customer'));
  for(const participant of ordered){
    for(const session of participant?.sessions||[]){
      const values=Array.isArray(session?.callbackNumbers)?session.callbackNumbers:[session?.callbackNumbers];
      for(const value of values){
        const phone=readablePhone(typeof value==='string'?value:value?.callbackNumber||value?.number||value?.value);
        if(phone)return phone;
      }
    }
  }
  return '';
}

export function summarizeConversation(conversation: any, userNames: Record<string, string> = {}) {
  const participants = conversation?.participants || [];
  const agents = new Set<string>();
  const flows = new Set<string>();
  const queues = new Set(conversationQueueNames(conversation));
  const wrapUpNames = conversationWrapUpCodeNames(conversation);
  const wrapUp = wrapUpNames[wrapUpNames.length - 1] || '';
  const readableQueues = [...queues].filter(name => readableName(name));

  for (const participant of participants) {
    const participantName = readableName(participant?.participantName);
    const userId = participantUserId(participant);
    const resolvedUserName = readableName(userNames[userId] || userNames[participant?.participantName]);

    if (participant?.purpose === 'agent') {
      const agentName = resolvedUserName || participantName;
      if (agentName && !GENERIC_AGENT_NAMES.has(agentName.toLowerCase())) agents.add(agentName);
    }
    if (['ivr', 'flow', 'botflow'].includes(String(participant?.purpose || '').toLowerCase())) {
      const flowName = participantFlowName(participant)
        || participantName
        || resolvedUserName
        || 'IVR flow';
      flows.add(flowName);
    }

  }

  const hasBot = flows.size > 0;
  return {
    conversationId: conversation.conversationId,
    conversationStart: conversation.conversationStart,
    conversationEnd: conversation.conversationEnd,
    direction: conversation.originatingDirection || 'unknown',
    callbackNumber: firstCallbackNumber(participants),
    ani: firstPhone(participants, 'ani'),
    dnis: firstPhone(participants, 'dnis'),
    agents: [...agents],
    flows: [...flows],
    participants: participantLines(participants, userNames),
    queues: readableQueues,
    wrapUp,
    durationSeconds: conversation.conversationStart && conversation.conversationEnd
      ? Math.round((Date.parse(conversation.conversationEnd) - Date.parse(conversation.conversationStart)) / 1000)
      : null,
    interactionType: agents.size && hasBot ? 'Bot to Agent' : agents.size > 1 ? 'Multi-Agent' : agents.size ? 'Human Agent' : hasBot ? 'Bot Only' : 'Unknown',
  };
}
