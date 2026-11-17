/** Convert a wall-clock date/time in an IANA zone into an ISO UTC timestamp. */
export function localDateTimeToUtc(date: string, time: string, timezone: string): string {
  const [year, month, day] = date.split('-').map(Number);
  const [hour, minute] = time.split(':').map(Number);
  if (![year, month, day, hour, minute].every(Number.isFinite)) throw new Error('Enter a valid local date and time.');
  const wallClock = Date.UTC(year, month - 1, day, hour, minute, 0);
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: timezone, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  });
  let instant = wallClock;
  for (let attempt = 0; attempt < 4; attempt++) {
    const values = Object.fromEntries(formatter.formatToParts(new Date(instant)).map(part => [part.type, part.value]));
    const displayedAsUtc = Date.UTC(Number(values.year), Number(values.month) - 1, Number(values.day), Number(values.hour), Number(values.minute), Number(values.second));
    const offset = displayedAsUtc - Math.floor(instant / 1000) * 1000;
    const next = wallClock - offset;
    if (next === instant) break;
    instant = next;
  }
  const check = Object.fromEntries(formatter.formatToParts(new Date(instant)).map(part => [part.type, part.value]));
  if (Number(check.year) !== year || Number(check.month) !== month || Number(check.day) !== day || Number(check.hour) !== hour || Number(check.minute) !== minute) {
    throw new Error('This local time does not exist in the selected timezone because of a clock change.');
  }
  return new Date(instant).toISOString();
}
