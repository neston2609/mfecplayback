export function transcriptionErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : 'Transcription request failed.';
  const genericFailure = /^Request failed \((\d{3})\)$/.exec(message);
  if (!genericFailure || Number(genericFailure[1]) < 500) return message;
  return `${message}. Check Speech and Text Analytics settings and Genesys service-account transcript permissions.`;
}
