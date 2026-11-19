import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export type ChangeRequestSize = 'high-effort' | 'small' | 'ui';

const VERSION_PATTERN = /^(\d+)\.(\d+)\.(\d+)$/;

export function nextAppVersion(current: string, size: ChangeRequestSize): string {
  const match = VERSION_PATTERN.exec(current);
  if (!match) throw new Error(`Invalid app version "${current}". Expected x.y.z.`);

  const [major, minor, patch] = match.slice(1).map(Number);
  if (![major, minor, patch].every(Number.isSafeInteger)) throw new Error(`Invalid app version "${current}".`);

  if (size === 'high-effort') return `${major + 1}.0.0`;
  if (size === 'small') return `${major}.${minor + 1}.0`;
  if (size === 'ui') return `${major}.${minor}.${patch + 1}`;
  throw new Error(`Unknown CR size "${String(size)}". Use high-effort, small, or ui.`);
}

function readJson(filePath: string): { value: Record<string, any>; newline: string } {
  const text = fs.readFileSync(filePath, 'utf8');
  return { value: JSON.parse(text) as Record<string, any>, newline: text.includes('\r\n') ? '\r\n' : '\n' };
}

function writeJson(filePath: string, value: Record<string, any>, newline: string) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2).replace(/\n/g, newline)}${newline}`, 'utf8');
}

export function bumpProjectVersion(root: string, size: ChangeRequestSize): { previous: string; version: string } {
  const packagePath = path.join(root, 'package.json');
  const lockPath = path.join(root, 'package-lock.json');
  const pkg = readJson(packagePath);
  const lock = readJson(lockPath);
  const previous = String(pkg.value.version || '');
  const version = nextAppVersion(previous, size);

  if (lock.value.name !== pkg.value.name || lock.value.packages?.['']?.name !== pkg.value.name) {
    throw new Error('package.json and package-lock.json do not describe the same root package.');
  }

  pkg.value.version = version;
  lock.value.version = version;
  lock.value.packages[''].version = version;
  writeJson(packagePath, pkg.value, pkg.newline);
  writeJson(lockPath, lock.value, lock.newline);
  return { previous, version };
}

function parseChangeRequestSize(value: string | undefined): ChangeRequestSize {
  if (value === 'high-effort' || value === 'small' || value === 'ui') return value;
  throw new Error('Usage: npm run version:high-effort | npm run version:small | npm run version:ui');
}

const entryPoint = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (entryPoint && fileURLToPath(import.meta.url) === entryPoint) {
  try {
    const size = parseChangeRequestSize(process.argv[2] || (process.env.npm_lifecycle_event === 'version:high-effort' ? 'high-effort' : process.env.npm_lifecycle_event === 'version:small' ? 'small' : process.env.npm_lifecycle_event === 'version:ui' ? 'ui' : undefined));
    const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
    const { previous, version } = bumpProjectVersion(root, size);
    console.log(`CR type: ${size}`);
    console.log(`MFEC Recording Explorer version: ${previous} -> ${version}`);
    console.log('Commit the package.json and package-lock.json version changes with this CR, then run the normal build/deploy flow.');
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Version bump failed.');
    process.exitCode = 1;
  }
}
