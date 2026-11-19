import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
const script = fileURLToPath(new URL('./inventory-ts.mjs', import.meta.url));
const sdk = fileURLToPath(new URL('../../sdk/node-ts', import.meta.url));
const inventory = root => JSON.parse(execFileSync(process.execPath, [script, root, sdk], {encoding: 'utf8'}));

test('follows public nested, renamed, namespace and cyclic re-exports without leaking private exports', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'msb-ts-inventory-'));
  try {
    mkdirSync(path.join(root, 'src/policy'), {recursive: true});
    const files = {
      'index.ts': `export * from './policy/index.js'; export { Worker as Task } from './worker.js'; export * as policies from './policy/types.js'; import type * as Types from './policy/types.js'; export const PublicRule = {}; export type PublicRule = Types.Rule;`,
      'policy/index.ts': `export * from './types.js'; export * from '../index.js';`,
      'policy/types.ts': `export type Action = 'allow' | 'deny'; export interface Rule { action: Action; }`,
      'worker.ts': `export class Worker { private hidden = 0; protected internal() {} public run() {} } export const notReexported = 1;`,
      'internal.ts': `export const privateModule = 1;`,
    };
    for (const [name, text] of Object.entries(files)) writeFileSync(path.join(root, 'src', name), text);
    const rows = inventory(root), names = rows.map(r => r.symbol);
    for (const name of ['Action', 'Rule', 'Rule.action', 'Task', 'Task.run', 'policies.Rule.action', 'PublicRule.action']) assert.ok(names.includes(name), name);
    for (const name of ['Worker', 'Task.hidden', 'Task.internal', 'notReexported', 'privateModule']) assert.ok(!names.includes(name), name);
    assert.equal(names.filter(n => n === 'Action').length, 1);
    assert.equal(rows.find(r => r.symbol === 'Rule.action').file, 'sdk/node-ts/src/policy/types.ts');
  } finally { rmSync(root, {recursive: true, force: true}); }
});

test('inventories the SDK public network declarations and fields', () => {
  const rows = inventory(sdk);
  for (const name of ['Action', 'Direction', 'NetworkProfile', 'Rule.action']) assert.ok(rows.some(r => r.symbol === name && r.file.endsWith('/policy/types.ts')), name);
  // An internal declaration can supply an explicitly exported public alias.
  // Unexported implementation symbols themselves must stay out of the surface.
  for (const name of ['nativeConstructor', 'defaultBinding', 'registerFallback']) assert.ok(!rows.some(r => r.symbol === name), name);
});
