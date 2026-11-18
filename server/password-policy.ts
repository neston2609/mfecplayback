export const PASSWORD_MIN_LENGTH = 8;

export type PasswordPolicy = {
  minLength: boolean;
  hasLetter: boolean;
  hasNumberOrSpecial: boolean;
  matchesConfirmation: boolean;
};

export function checkPasswordPolicy(password: string, confirmation = password): PasswordPolicy {
  return {
    minLength: [...password].length >= PASSWORD_MIN_LENGTH,
    hasLetter: /\p{L}/u.test(password),
    hasNumberOrSpecial: /\p{N}|[^\p{L}\p{M}\p{N}\s]/u.test(password),
    matchesConfirmation: confirmation.length > 0 && password === confirmation,
  };
}

export function isPasswordPolicySatisfied(password: string, confirmation = password) {
  return Object.values(checkPasswordPolicy(password, confirmation)).every(Boolean);
}
