export type PasswordChecks = {
  minLength: boolean;
  hasLetter: boolean;
  hasNumberOrSpecial: boolean;
  matchesConfirmation: boolean;
};

export function getPasswordChecks(password: string, confirmation = password): PasswordChecks {
  return {
    minLength: [...password].length >= 8,
    hasLetter: /\p{L}/u.test(password),
    hasNumberOrSpecial: /\p{N}|[^\p{L}\p{M}\p{N}\s]/u.test(password),
    matchesConfirmation: confirmation.length > 0 && password === confirmation,
  };
}
