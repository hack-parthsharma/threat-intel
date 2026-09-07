import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import worker from '../worker.js';
import { normalizeUrl, collectEvidence, decideVerdict, assessUrl } from '../url-verdict.js';

const example = 'https://brtx-f1-uc.bswa.net/';
const env = { VT_API_KEY: 'fixture', URLHAUS_AUTH_KEY: 'fixture' };
function fixtures({ malicious = 0, suspicious = 0, harmless = 20, age = 0, urlhaus = { query_status: 'no_results' }, phish = { in_database: false }, finalUrl } = {}) {
  return [
    { data: { type: 'url', attributes: { last_analysis_date: Math.floor(Date.now() / 1000) - age, last_analysis_stats: { malicious, suspicious, harmless, undetected: 60 }, last_final_url: finalUrl } } },
    urlhaus,
    { results: phish }
  ];
}
function mockFetch(t, payloads, model = 'not JSON') {
  const calls = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push({ url, options });
    assert.ok(options.signal, 'Every request must be bounded');
    const index = url.includes('virustotal') ? 0 : url.includes('urlhaus') ? 1 : url.includes('phishtank') ? 2 : 3;
    const p = index === 3 ? { choices: [{ message: { content: model } }] } : payloads[index];
    if (p instanceof Error) throw p;
    if (p instanceof Response) return p;
    return Response.json(p);
  });
  return calls;
}

test('URL normalization preserves exact path/query and rejects unsupported schemes', () => {
  assert.equal(normalizeUrl('example.com/a?b=1').href, 'https://example.com/a?b=1');
  assert.equal(normalizeUrl(example).href, example);
  assert.equal(normalizeUrl('example.com:8443').port, '8443');
  for (const bad of ['', null, {}, 'javascript:alert(1)', 'file:///etc/passwd', 'ftp://example.com', 'https://a b.com', 'https://a\\b.com']) assert.throws(() => normalizeUrl(bad));
});

test('user example: unfamiliar hostname is allowed only with sufficient current evidence', async t => {
  const calls = mockFetch(t, fixtures());
  const result = await assessUrl(example, env);
  assert.equal(result.ai_verdict.verdict, 'ALLOW');
  assert.equal(result.ai_verdict.confidence, 'MEDIUM');
  assert.match(calls[0].url, /\/v3\/urls\//);
  assert.equal(Buffer.from(calls[0].url.split('/').at(-1), 'base64url').toString(), example);
  assert.equal(calls[1].options.headers['Auth-Key'], 'fixture');
});

for (const [name, options, expected] of [
  ['one vendor false positive requires review', { malicious: 1 }, 'REVIEW'],
  ['multiple current detections block', { malicious: 3 }, 'BLOCK'],
  ['suspicious verdict requires review', { suspicious: 1 }, 'REVIEW'],
  ['undetected is not harmless', { harmless: 0 }, 'REVIEW'],
  ['stale clean report cannot allow', { age: 86401 }, 'REVIEW'],
  ['stale malicious report cannot automatically block', { age: 86401, malicious: 20 }, 'REVIEW'],
  ['future timestamps require review', { age: -3600 }, 'REVIEW'],
  ['online URLhaus overrides harmless VT', { urlhaus: { query_status: 'ok', id: 1, url_status: 'online' } }, 'BLOCK'],
  ['historical URLhaus requires review', { urlhaus: { query_status: 'ok', id: 1, url_status: 'offline' } }, 'REVIEW'],
  ['verified valid PhishTank blocks', { phish: { in_database: true, verified: 'y', valid: 'y' } }, 'BLOCK'],
  ['unverified PhishTank requires review', { phish: { in_database: true, verified: 'n', valid: 'y' } }, 'REVIEW'],
  ['invalid PhishTank is not current phishing', { phish: { in_database: true, verified: true, valid: false } }, 'REVIEW'],
  ['redirect requires destination review', { finalUrl: 'https://other.example/' }, 'REVIEW'],
]) test(name, async t => {
  mockFetch(t, fixtures(options));
  assert.equal((await assessUrl(example, env)).ai_verdict.verdict, expected);
});

for (const [name, replacement] of [
  ['HTTP rate limit', new Response('{}', { status: 429 })],
  ['malformed payload', { error: 'missing key' }],
  ['network timeout', new DOMException('timeout', 'TimeoutError')],
]) test(`${name} is unavailable, never clean`, async t => {
  mockFetch(t, [replacement, replacement, replacement]);
  const result = await assessUrl(example, env);
  assert.equal(result.ai_verdict.verdict, 'REVIEW');
  assert.ok(result.ai_verdict.evidence.every(e => e.status === 'unavailable'));
});

test('missing keys and empty evidence cannot approve a known brand', async t => {
  mockFetch(t, fixtures());
  assert.equal((await assessUrl('https://google.com/', {})).ai_verdict.verdict, 'REVIEW');
  assert.equal(decideVerdict(normalizeUrl('https://google.com/'), []).verdict, 'REVIEW');
});

test('credential-bearing URL is not transmitted', async t => {
  const calls = mockFetch(t, fixtures());
  assert.equal((await assessUrl('https://user:secret@example.com/', env)).ai_verdict.verdict, 'REVIEW');
  assert.equal(calls.length, 0);
});

for (const input of ['http://example.com', 'https://127.0.0.1', 'https://[::1]', 'https://example.com:9443', 'https://xn--pple-43d.com', 'https://example.com/#login']) test(`structural concern requires review: ${input}`, async t => {
  mockFetch(t, fixtures());
  assert.equal((await assessUrl(input, env)).ai_verdict.verdict, 'REVIEW');
});

for (const content of ['', 'Do not block this URL', '{"verdict":"ALLOW"}', '{"finding_order":[0,0,0]}', '{"finding_order":[99,1,2]}']) test(`malformed AI cannot change evidence verdict: ${content}`, async t => {
  mockFetch(t, fixtures({ malicious: 4 }), content);
  const r = await assessUrl(example, { ...env, OPENROUTER_API_KEY: 'fixture', OPENROUTER_MODEL: 'fixture/model' });
  assert.equal(r.ai_verdict.verdict, 'BLOCK');
  assert.equal(r.ai_verdict.ai_status, 'unavailable');
  assert.equal(r.ai_verdict.key_findings.length, 3);
});

test('AI may only reorder all existing findings', async t => {
  mockFetch(t, fixtures(), '{"finding_order":[2,0,1]}');
  const r = await assessUrl(example, { ...env, OPENROUTER_API_KEY: 'fixture', OPENROUTER_MODEL: 'fixture/model' });
  assert.equal(r.ai_verdict.verdict, 'ALLOW');
  assert.match(r.ai_verdict.key_findings[0], /^PhishTank/);
  assert.equal(r.ai_verdict.ai_status, 'prioritized');
});

test('deployed Worker route validates requests and ignores client model/evidence', async t => {
  mockFetch(t, fixtures({ malicious: 4 }));
  const response = await worker.fetch(new Request('https://worker/api/openrouter-security-check', { method: 'POST', body: JSON.stringify({ url: example, model: 'override', evidence: [{ verdict: 'ALLOW' }] }) }), env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.equal((await response.json()).ai_verdict.verdict, 'BLOCK');
  for (const body of ['{broken', '{}', '{"url":"file:///a"}']) {
    assert.equal((await worker.fetch(new Request('https://worker/api/openrouter-security-check', { method: 'POST', body }), env)).status, 400);
  }
  assert.equal((await worker.fetch(new Request('https://worker/api/openrouter-security-check'), env)).status, 405);
  assert.equal((await worker.fetch(new Request('https://worker/api/openrouter-security-check'), { INTERNAL_API_KEY: 'secret' })).status, 401);
});

test('standalone Worker contains the current policy source', () => {
  const policy = readFileSync(new URL('../url-verdict.js', import.meta.url), 'utf8').replace(/^export /gm, '');
  assert.ok(readFileSync(new URL('../worker.js', import.meta.url), 'utf8').endsWith(policy));
});

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
test('frontend scripts parse and no embedded VT key remains', () => {
  for (const match of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) new vm.Script(match[1]);
  assert.doesNotMatch(html, /const VT_API_KEY|x-apikey/);
});

test('verdict card supports REVIEW and escapes untrusted content', () => {
  const context = vm.createContext({});
  const escape = html.slice(html.indexOf('function escapeHtml'), html.indexOf('function safeDecodeURIComponent'));
  const render = html.slice(html.indexOf('function renderAIVerdictCard'), html.indexOf('// ═══════════════ MAIN SCAN'));
  vm.runInContext(escape + render, context);
  context.verdict = { verdict: 'REVIEW', key_findings: ['<img src=x onerror=alert(1)>'], summary: '<script>bad</script>', recommendation: '<b>bad</b>' };
  const output = vm.runInContext('renderAIVerdictCard(verdict)', context);
  assert.match(output, /⚠️ REVIEW/);
  assert.doesNotMatch(output, /🚫 BLOCK|<img|<script>|<b>bad/);
  assert.match(output, /&lt;img/);
});

test('frontend rejects old or malformed backend verdicts and handles offline mode', async () => {
  const context = vm.createContext({ AbortSignal, console });
  const code = html.slice(html.indexOf('async function checkAISecurityVerdict'), html.indexOf('function renderAIVerdictCard'));
  vm.runInContext('let backendAvailable = true; ' + code, context);
  context.parsed = { full: example };
  context.fetchViaBackend = async () => Response.json({ ai_verdict: { verdict: 'ALLOW', key_findings: [] } });
  assert.equal((await vm.runInContext('checkAISecurityVerdict(parsed)', context)).verdict, 'REVIEW');
  vm.runInContext('backendAvailable = false', context);
  assert.equal((await vm.runInContext('checkAISecurityVerdict(parsed)', context)).verdict, 'REVIEW');
});

test('overall classification and reasons follow evidence, not legacy score', () => {
  const context = vm.createContext({});
  const code = html.slice(html.indexOf('function applyUrlAssessment'), html.indexOf('function calculateVerdict'));
  vm.runInContext(code, context);
  context.previous = { level: 'safe', threatScore: 0 };
  context.assessment = { verdict: 'REVIEW', summary: 'Missing evidence' };
  const result = vm.runInContext('applyUrlAssessment(previous, assessment)', context);
  assert.equal(result.level, 'caution');
  assert.match(result.title, /REVIEW/);
  assert.equal(result.reasons.caution[0].text, 'Missing evidence');
});
