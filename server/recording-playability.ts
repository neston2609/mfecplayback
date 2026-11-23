import { db } from './db/index.js';

export type RecordingPlayabilityKey = {
  connectionId: string;
  conversationId: string;
  recordingId: string;
};

export function getUnplayableRecordingKeys(connectionId: string, conversationIds: string[]): Set<string> {
  const ids = [...new Set(conversationIds.filter(Boolean))];
  const result = new Set<string>();
  for (let offset = 0; offset < ids.length; offset += 400) {
    const batch = ids.slice(offset, offset + 400);
    if (!batch.length) continue;
    const rows = db.prepare(`SELECT conversation_id AS conversationId,recording_id AS recordingId
      FROM recording_playability
      WHERE connection_id=? AND is_unplayable=1 AND conversation_id IN (${batch.map(() => '?').join(',')})`)
      .all(connectionId, ...batch) as { conversationId: string; recordingId: string }[];
    for (const row of rows) result.add(`${row.conversationId}\u0000${row.recordingId}`);
  }
  return result;
}

export function setRecordingUnplayable(key: RecordingPlayabilityKey, unplayable: boolean, userId: string): void {
  if (unplayable) {
    db.prepare(`INSERT INTO recording_playability(connection_id,conversation_id,recording_id,is_unplayable,marked_by,updated_at)
      VALUES(?,?,?,1,?,?)
      ON CONFLICT(connection_id,conversation_id,recording_id) DO UPDATE SET is_unplayable=1,marked_by=excluded.marked_by,updated_at=excluded.updated_at`)
      .run(key.connectionId, key.conversationId, key.recordingId, userId, new Date().toISOString());
  } else {
    db.prepare('DELETE FROM recording_playability WHERE connection_id=? AND conversation_id=? AND recording_id=?')
      .run(key.connectionId, key.conversationId, key.recordingId);
  }
}
