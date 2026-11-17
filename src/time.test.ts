import { describe, expect, it } from 'vitest';
import { localDateTimeToUtc } from './time';

describe('localDateTimeToUtc', () => {
  it('converts the default Bangkok timezone to UTC', () => {
    expect(localDateTimeToUtc('2026-11-17', '10:30', 'Asia/Bangkok')).toBe('2026-11-17T03:30:00.000Z');
  });
  it('applies daylight-saving offsets for a selected timezone', () => {
    expect(localDateTimeToUtc('2026-07-17', '10:30', 'America/New_York')).toBe('2026-07-17T14:30:00.000Z');
  });
  it('converts UTC wall-clock values without an offset', () => {
    expect(localDateTimeToUtc('2026-11-17', '10:30', 'UTC')).toBe('2026-11-17T10:30:00.000Z');
  });
});
