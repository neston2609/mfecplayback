const THAI_COUNTRY_CODE = '66';

/** Normalize phone-number input while preserving the significant country/local prefix. */
export function normalizePhoneSearch(value: unknown): string {
  const raw = String(value ?? '').trim();
  if (!raw || /(?:@|^sips?:)/i.test(raw)) return '';
  let digits = raw.replace(/\D/g, '');
  if (!digits) return '';

  // Treat common international access prefixes the same as a leading plus.
  if (digits.startsWith('0066')) digits = digits.slice(2);
  else if (digits.startsWith('01166')) digits = digits.slice(3);

  // Thai mobile/landline numbers are interchangeable as 0xxxxxxxxx,
  // 66xxxxxxxxx, or +66xxxxxxxxx in CRM/Genesys data and user searches.
  if (digits.startsWith(THAI_COUNTRY_CODE)) {
    const nationalNumber = digits.slice(THAI_COUNTRY_CODE.length);
    digits = `0${nationalNumber}`;
  }
  return digits;
}

export function phoneSearchMatches(value: unknown, query: unknown, allowSubstring = true): boolean {
  const normalizedValue = normalizePhoneSearch(value);
  const normalizedQuery = normalizePhoneSearch(query);
  return Boolean(normalizedValue && normalizedQuery && (allowSubstring ? normalizedValue.includes(normalizedQuery) : normalizedValue === normalizedQuery));
}

type PhoneField = 'phone' | 'dnis';

function collectPhoneValues(value: unknown, results: string[], field: PhoneField, key = ''): void {
  if (!value || typeof value !== 'object') {
    const keyMatches = field === 'dnis'
      ? /^dnis$/i.test(key)
      : /^(?:ani|callbacknumber|callback_number|phonenumber)$/i.test(key);
    if (typeof value === 'string' && keyMatches) results.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectPhoneValues(item, results, field, key);
    return;
  }
  for (const [childKey, childValue] of Object.entries(value)) collectPhoneValues(childValue, results, field, childKey);
}

/** Search the requested customer-phone field anywhere in Analytics details. */
export function conversationHasPhoneMatch(conversation: unknown, query: unknown, field: PhoneField = 'phone'): boolean {
  const values: string[] = [];
  collectPhoneValues(conversation, values, field);
  return values.some(value => phoneSearchMatches(value, query, false));
}
