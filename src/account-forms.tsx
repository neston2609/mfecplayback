import type { PasswordChecks } from './password-policy';

export type UserProfile = {
  email: string;
  phone: string;
  firstName: string;
  lastName: string;
  nickname: string;
  jobTitle: string;
  division: string;
  department: string;
};

export const EMPTY_PROFILE: UserProfile = {
  email: '', phone: '', firstName: '', lastName: '', nickname: '', jobTitle: '', division: '', department: '',
};

const profileFields: [keyof UserProfile, string, string][] = [
  ['email', 'Email', 'email'], ['phone', 'Phone number', 'tel'],
  ['firstName', 'First name', 'text'], ['lastName', 'Last name', 'text'],
  ['nickname', 'Nickname', 'text'], ['jobTitle', 'Position / job title', 'text'],
  ['division', 'Division', 'text'], ['department', 'Department', 'text'],
];

export function ProfileFields({ profile, onChange }: { profile: UserProfile; onChange: (key: keyof UserProfile, value: string) => void }) {
  return <div className="profile-fields">{profileFields.map(([key, label, type]) => <label className="field" key={key}>
    <span>{label}</span><input type={type} maxLength={key === 'phone' ? 40 : key === 'email' ? 320 : 120} autoComplete={key === 'email' ? 'email' : key === 'phone' ? 'tel' : 'off'} value={profile[key]} onChange={event => onChange(key, event.target.value)} />
  </label>)}</div>;
}

export function PasswordRequirements({ checks }: { checks: PasswordChecks }) {
  const rows: [keyof PasswordChecks, string][] = [
    ['minLength', 'At least 8 characters'],
    ['hasLetter', 'At least one letter (uppercase or lowercase)'],
    ['hasNumberOrSpecial', 'At least one number or special character'],
    ['matchesConfirmation', 'Password confirmation matches'],
  ];
  return <div className="password-requirements" aria-live="polite"><b>Password requirements</b>{rows.map(([key, label]) => <label key={key} className={checks[key] ? 'requirement-passed' : ''}>
    <input type="checkbox" checked={checks[key]} readOnly tabIndex={-1} aria-label={`${label}: ${checks[key] ? 'met' : 'not met'}`} />
    <span>{label}</span>
  </label>)}</div>;
}
