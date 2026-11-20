import { describe, expect, it } from 'vitest';
import { transcriptionErrorMessage } from './transcription-error.js';

describe('transcriptionErrorMessage', () => {
  it('adds useful guidance when the API response has no readable error message', () => {
    expect(transcriptionErrorMessage(new Error('Request failed (502)'))).toBe(
      'Request failed (502). Check Speech and Text Analytics settings and Genesys service-account transcript permissions.',
    );
  });

  it('preserves actionable API errors and authentication failures', () => {
    expect(transcriptionErrorMessage(new Error('Genesys returned a transcript URL on an untrusted host.'))).toBe(
      'Genesys returned a transcript URL on an untrusted host.',
    );
    expect(transcriptionErrorMessage(new Error('Sign in required.'))).toBe('Sign in required.');
  });
});
