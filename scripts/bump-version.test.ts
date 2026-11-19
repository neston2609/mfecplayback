import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { bumpProjectVersion, nextAppVersion } from './bump-version.js';

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe('application versioning', () => {
  it('bumps the high-effort component and resets the lower components', () => {
    expect(nextAppVersion('1.8.6', 'high-effort')).toBe('2.0.0');
  });

  it('bumps the small-CR component and resets the UI component', () => {
    expect(nextAppVersion('1.8.6', 'small')).toBe('1.9.0');
  });

  it('bumps the UI-only component', () => {
    expect(nextAppVersion('1.8.6', 'ui')).toBe('1.8.7');
  });

  it('updates package and lockfile root versions together', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'mfec-version-test-'));
    temporaryDirectories.push(root);
    writeFileSync(path.join(root, 'package.json'), `${JSON.stringify({ name: 'test-app', version: '1.0.0' }, null, 2)}\n`);
    writeFileSync(path.join(root, 'package-lock.json'), `${JSON.stringify({ name: 'test-app', version: '1.0.0', packages: { '': { name: 'test-app', version: '1.0.0' }, 'node_modules/example': { version: '1.0.0' } } }, null, 2)}\n`);

    expect(bumpProjectVersion(root, 'small')).toEqual({ previous: '1.0.0', version: '1.1.0' });
    const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
    const lock = JSON.parse(readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
    expect(pkg.version).toBe('1.1.0');
    expect(lock.version).toBe('1.1.0');
    expect(lock.packages[''].version).toBe('1.1.0');
    expect(lock.packages['node_modules/example'].version).toBe('1.0.0');
  });

  it('rejects invalid versions', () => {
    expect(() => nextAppVersion('1.0', 'small')).toThrow('Expected x.y.z');
  });
});
