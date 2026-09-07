import { readFileSync, writeFileSync } from 'node:fs';
const marker = '// BEGIN GENERATED URL VERDICT';
const worker = readFileSync(new URL('../worker.js', import.meta.url), 'utf8').split(marker)[0];
const policy = readFileSync(new URL('../url-verdict.js', import.meta.url), 'utf8').replace(/^export /gm, '');
writeFileSync(new URL('../worker.js', import.meta.url), worker + marker + '\n' + policy);
