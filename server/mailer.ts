import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';

export type SmtpSettings = {
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password: string;
  fromName: string;
  fromEmail: string;
  rejectUnauthorized: boolean;
};

export type PublicSmtpSettings = Omit<SmtpSettings, 'password'> & { passwordConfigured: boolean };

export function parseSmtpSettings(value: unknown): SmtpSettings {
  if (!value || typeof value !== 'object') throw new Error('SMTP settings are invalid.');
  const input = value as Record<string, unknown>;
  const host = typeof input.host === 'string' ? input.host.trim() : '';
  const username = typeof input.username === 'string' ? input.username.trim() : '';
  const fromEmail = typeof input.fromEmail === 'string' ? input.fromEmail.trim() : '';
  const fromName = typeof input.fromName === 'string' ? input.fromName.trim() : '';
  const port = Number(input.port);
  if (!host || host.length > 253 || /[\s/@]/.test(host)) throw new Error('Enter a valid SMTP server host.');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('SMTP port must be between 1 and 65535.');
  if (typeof input.secure !== 'boolean') throw new Error('Choose whether SMTP uses implicit TLS.');
  if (!username || username.length > 320) throw new Error('Enter the SMTP username.');
  if (!fromEmail || fromEmail.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fromEmail)) throw new Error('Enter a valid sender email address.');
  if (fromName.length > 120) throw new Error('Sender name cannot exceed 120 characters.');
  if (typeof input.password !== 'string' || input.password.length > 1024) throw new Error('SMTP password is invalid.');
  if (input.rejectUnauthorized !== true) throw new Error('SMTP TLS certificate validation must remain enabled.');
  return { host, port, secure: input.secure, username, password: input.password, fromName, fromEmail, rejectUnauthorized: input.rejectUnauthorized };
}

export function publicSmtpSettings(settings: SmtpSettings, passwordConfigured: boolean): PublicSmtpSettings {
  const { password: _password, ...safe } = settings;
  return { ...safe, passwordConfigured };
}

export function createSmtpTransport(settings: SmtpSettings): Transporter {
  return nodemailer.createTransport({
    host: settings.host,
    port: settings.port,
    secure: settings.secure,
    requireTLS: !settings.secure,
    auth: { user: settings.username, pass: settings.password },
    tls: { rejectUnauthorized: settings.rejectUnauthorized },
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
  });
}

export async function sendConfiguredEmail(settings: SmtpSettings, input: { to: string; subject: string; text: string }) {
  const to = input.to.trim();
  if (!to || to.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) throw new Error('Enter a valid recipient email address.');
  if (!input.subject.trim() || input.subject.length > 200) throw new Error('Email subject is required and must be at most 200 characters.');
  if (!input.text.trim() || input.text.length > 20_000) throw new Error('Email message is required and must be at most 20000 characters.');
  const transport = createSmtpTransport(settings);
  try {
    return await transport.sendMail({
      from: { name: settings.fromName || settings.username, address: settings.fromEmail },
      to,
      subject: input.subject,
      text: input.text,
    });
  } finally {
    transport.close();
  }
}
