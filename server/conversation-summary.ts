const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

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

export function participantLines(participants: any[], userNames: Record<string, string> = {}): ParticipantLine[] {
  return participants.map(participant => {
    const purpose = typeof participant?.purpose === 'string' ? participant.purpose : '';
    const normalized = purpose.toLowerCase();
    const participantName = readableName(participant?.participantName);
    const userId = typeof participant?.userId === 'string' ? participant.userId : '';
    let displayName = participantName || '—';

    if (normalized === 'customer') {
      displayName = `${participantPhone(participant, 'ani')} -> ${participantPhone(participant, 'dnis')}`;
    } else if (normalized === 'agent') {
      displayName = readableName(userNames[userId]) || participantName || 'Agent';
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

export function summarizeConversation(conversation: any, userNames: Record<string, string> = {}) {
  const participants = conversation?.participants || [];
  const agents = new Set<string>();
  const flows = new Set<string>();
  const queues = new Set<string>();
  let wrapUp = '';

  for (const participant of participants) {
    const participantName = readableName(participant?.participantName);
    const userId = typeof participant?.userId === 'string' ? participant.userId : '';
    const resolvedUserName = readableName(userNames[userId] || userNames[participant?.participantName]);

    if (participant?.purpose === 'agent') agents.add(resolvedUserName || participantName || 'Agent');
    if (['ivr', 'flow', 'botflow'].includes(String(participant?.purpose || '').toLowerCase())) {
      const flowName = participantFlowName(participant)
        || participantName
        || resolvedUserName
        || 'IVR flow';
      flows.add(flowName);
    }

    for (const session of participant?.sessions || []) {
      if (session?.queueName) queues.add(session.queueName);
      for (const segment of session?.segments || []) if (segment?.wrapUpCode) wrapUp = segment.wrapUpCode;
    }
  }

  const hasBot = flows.size > 0;
  return {
    conversationId: conversation.conversationId,
    conversationStart: conversation.conversationStart,
    conversationEnd: conversation.conversationEnd,
    direction: conversation.originatingDirection || 'unknown',
    ani: firstPhone(participants, 'ani'),
    dnis: firstPhone(participants, 'dnis'),
    agents: [...agents],
    flows: [...flows],
    participants: participantLines(participants, userNames),
    queues: [...queues],
    wrapUp,
    durationSeconds: conversation.conversationStart && conversation.conversationEnd
      ? Math.round((Date.parse(conversation.conversationEnd) - Date.parse(conversation.conversationStart)) / 1000)
      : null,
    interactionType: agents.size && hasBot ? 'Bot to Agent' : agents.size > 1 ? 'Multi-Agent' : agents.size ? 'Human Agent' : hasBot ? 'Bot Only' : 'Unknown',
  };
}
