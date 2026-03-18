const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET,POST,OPTIONS',
  'access-control-allow-headers': 'Content-Type, Authorization',
};

const ROUTES = {
  '/api/urlhaus': handleUrlhaus,
  '/api/threatfox': handleThreatFox,
  '/api/wayback': handleWayback,
  '/api/dns': handleDns,
  '/api/headers': handleHeaders,
  '/api/rdap': handleRdap,
  '/api/phishtank': handlePhishTank,
  '/api/abuseipdb': handleAbuseIpDb,
  '/api/crt': handleCrtSh,
  '/api/ipgeo': handleIpGeo,
  '/api/cfradar': handleCloudflareRadar,
  '/api/virustotal/domain': handleVirusTotalDomain,
  '/api/virustotal/votes': handleVirusTotalVotes,
  '/api/virustotal/file-report': handleVirusTotalFileReport,
  '/api/virustotal/upload': handleVirusTotalUpload,
  '/api/virustotal/analysis': handleVirusTotalAnalysis,
  '/api/metadefender/hash': handleMetaDefenderHash,
  '/api/metadefender/upload': handleMetaDefenderUpload,
  '/api/metadefender/report': handleMetaDefenderReport,
  '/api/malwarebazaar': handleMalwareBazaar,
  '/api/cerebras-summary': handleCerebrasSummary,
  '/api/openrouter-security-check': handleOpenRouterSecurityCheck,
};

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: JSON_HEADERS });
    }

    const url = new URL(request.url);
    if (url.pathname === '/health') {
      return jsonResponse({
        status: 'ok',
        timestamp: new Date().toISOString(),
        services: {
          virustotalConfigured: Boolean(env.VIRUSTOTAL_API_KEY),
          metadefenderConfigured: Boolean(env.METADEFENDER_API_KEY),
          abuseipdbConfigured: Boolean(env.ABUSEIPDB_API_KEY),
          cerebrasConfigured: Boolean(env.CEREBRAS_API_KEY),
          openrouterConfigured: Boolean(env.OPENROUTER_API_KEY),
        },
      });
    }

    const handler = ROUTES[url.pathname];
    if (!handler) {
      return jsonResponse({ error: `Route not found: ${url.pathname}` }, 404);
    }

    try {
      return await handler(request, env, url);
    } catch (error) {
      console.error('Worker error', url.pathname, error);
      return jsonResponse({ error: error.message || 'Internal server error' }, 500);
    }
  },
};

function jsonResponse(payload, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders },
  });
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    throw new Error('Request body must be valid JSON');
  }
}

function requireQuery(url, name) {
  const value = url.searchParams.get(name)?.trim();
  if (!value) throw new Error(`Missing required query parameter: ${name}`);
  return value;
}

function requireEnv(env, name) {
  const value = env[name];
  if (!value) throw new Error(`Missing required secret: ${name}`);
  return value;
}

async function proxyJson(target, init = {}) {
  const response = await fetch(target, init);
  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }

  if (!response.ok) {
    return jsonResponse({ error: data?.error || data?.message || `Upstream HTTP ${response.status}`, upstream: data }, response.status);
  }

  return jsonResponse(data, response.status);
}

async function handleUrlhaus(request) {
  const { url } = await readJson(request);
  if (!url) throw new Error('Missing required field: url');
  return proxyJson('https://urlhaus-api.abuse.ch/v1/url/', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ url }).toString(),
  });
}

async function handleThreatFox(request) {
  const { domain } = await readJson(request);
  if (!domain) throw new Error('Missing required field: domain');
  return proxyJson('https://threatfox-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query: 'search_ioc', search_term: domain }),
  });
}

async function handleWayback(_request, _env, url) {
  const domain = requireQuery(url, 'domain');
  return proxyJson(`https://archive.org/wayback/available?url=${encodeURIComponent(domain)}`);
}

async function handleDns(_request, _env, url) {
  const domain = requireQuery(url, 'domain');
  const type = url.searchParams.get('type') || 'A';
  return proxyJson(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`);
}

async function handleHeaders(request) {
  const { url } = await readJson(request);
  if (!url) throw new Error('Missing required field: url');

  const upstream = await fetch(url, {
    method: 'HEAD',
    redirect: 'follow',
    headers: { 'user-agent': 'threat-intel-worker/1.0' },
  });

  const headers = {};
  upstream.headers.forEach((value, key) => {
    headers[key] = value;
  });

  return jsonResponse({
    status: upstream.status,
    statusText: upstream.statusText,
    redirected: upstream.redirected,
    finalUrl: upstream.url,
    headers,
  });
}

async function handleRdap(_request, _env, url) {
  const domain = requireQuery(url, 'domain');
  return proxyJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
}

async function handlePhishTank(request) {
  const { url } = await readJson(request);
  if (!url) throw new Error('Missing required field: url');
  return proxyJson('https://checkurl.phishtank.com/checkurl/', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'user-agent': 'threat-intel-worker/1.0',
    },
    body: new URLSearchParams({ url, format: 'json', app_key: 'threat-intel-worker' }).toString(),
  });
}

async function handleAbuseIpDb(_request, env, url) {
  const ip = requireQuery(url, 'ip');
  const apiKey = requireEnv(env, 'ABUSEIPDB_API_KEY');
  return proxyJson(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`, {
    headers: {
      key: apiKey,
      accept: 'application/json',
    },
  });
}

async function handleCrtSh(_request, _env, url) {
  const domain = requireQuery(url, 'domain');
  return proxyJson(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`);
}

async function handleIpGeo(_request, _env, url) {
  const ip = requireQuery(url, 'ip');
  return proxyJson(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,regionName,city,isp,org,as,hosting,proxy,mobile,query`);
}

async function handleCloudflareRadar(_request, _env, url) {
  const domain = requireQuery(url, 'domain');
  return proxyJson(`https://radar.cloudflare.com/api/v0/domains/rank?domain=${encodeURIComponent(domain)}`);
}

async function handleVirusTotalDomain(_request, env, url) {
  const domain = requireQuery(url, 'domain');
  const apiKey = requireEnv(env, 'VIRUSTOTAL_API_KEY');
  return proxyJson(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
    headers: { 'x-apikey': apiKey },
  });
}

async function handleVirusTotalVotes(_request, env, url) {
  const domain = requireQuery(url, 'domain');
  const apiKey = requireEnv(env, 'VIRUSTOTAL_API_KEY');
  return proxyJson(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}/votes`, {
    headers: { 'x-apikey': apiKey },
  });
}

async function handleVirusTotalFileReport(_request, env, url) {
  const hash = requireQuery(url, 'hash');
  const apiKey = requireEnv(env, 'VIRUSTOTAL_API_KEY');
  return proxyJson(`https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}`, {
    headers: { 'x-apikey': apiKey },
  });
}

async function handleVirusTotalUpload(request, env) {
  const apiKey = requireEnv(env, 'VIRUSTOTAL_API_KEY');
  const formData = await request.formData();
  const upstream = await fetch('https://www.virustotal.com/api/v3/files', {
    method: 'POST',
    headers: { 'x-apikey': apiKey },
    body: formData,
  });
  return passThroughResponse(upstream);
}

async function handleVirusTotalAnalysis(_request, env, url) {
  const id = requireQuery(url, 'id');
  const apiKey = requireEnv(env, 'VIRUSTOTAL_API_KEY');
  return proxyJson(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(id)}`, {
    headers: { 'x-apikey': apiKey },
  });
}

async function handleMetaDefenderHash(_request, env, url) {
  const hash = requireQuery(url, 'hash');
  const apiKey = requireEnv(env, 'METADEFENDER_API_KEY');
  return proxyJson(`https://api.metadefender.com/v4/hash/${encodeURIComponent(hash)}`, {
    headers: { apikey: apiKey },
  });
}

async function handleMetaDefenderUpload(request, env) {
  const apiKey = requireEnv(env, 'METADEFENDER_API_KEY');
  const formData = await request.formData();
  const file = formData.get('file');
  if (!(file instanceof File)) throw new Error('Missing file in form-data payload');

  const upstream = await fetch('https://api.metadefender.com/v4/file', {
    method: 'POST',
    headers: {
      apikey: apiKey,
      filename: file.name,
      'content-type': 'application/octet-stream',
    },
    body: file.stream(),
  });

  return passThroughResponse(upstream);
}

async function handleMetaDefenderReport(_request, env, url) {
  const dataId = requireQuery(url, 'data_id');
  const apiKey = requireEnv(env, 'METADEFENDER_API_KEY');
  return proxyJson(`https://api.metadefender.com/v4/file/${encodeURIComponent(dataId)}`, {
    headers: { apikey: apiKey },
  });
}

async function handleMalwareBazaar(request) {
  const body = await readJson(request);
  return proxyJson('https://mb-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function handleCerebrasSummary(request, env) {
  const apiKey = requireEnv(env, 'CEREBRAS_API_KEY');
  const { prompt, model = 'llama3.1-8b', max_tokens = 700, temperature = 0.2 } = await readJson(request);
  if (!prompt?.trim()) throw new Error('Missing required field: prompt');

  const upstream = await fetch('https://api.cerebras.ai/v1/chat/completions', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model,
      max_tokens,
      temperature,
      messages: [
        { role: 'system', content: 'You are a concise cybersecurity analyst. Return only the requested content.' },
        { role: 'user', content: prompt },
      ],
    }),
  });

  const payload = await upstream.json();
  if (!upstream.ok) {
    return jsonResponse({ error: payload?.message || payload?.error || `Cerebras HTTP ${upstream.status}`, upstream: payload }, upstream.status);
  }

  const content = payload?.choices?.[0]?.message?.content || '';
  return jsonResponse({ summary: content, content, raw: payload });
}

async function handleOpenRouterSecurityCheck(request, env) {
  const apiKey = requireEnv(env, 'OPENROUTER_API_KEY');
  const { url, model = 'openai/gpt-4o-mini', max_tokens = 700, temperature = 0.1 } = await readJson(request);
  if (!url?.trim()) throw new Error('Missing required field: url');

  const systemPrompt = [
    'You are a security URL triage analyst.',
    'Assess whether the submitted URL should be allowed, blocked, or manually reviewed.',
    'Return valid JSON only with keys verdict, confidence, summary, reasons.',
    'verdict must be one of: allow, review, block.',
    'confidence must be an integer from 0 to 100.',
    'reasons must be an array of short strings.',
  ].join(' ');

  const userPrompt = `Perform security check of ${url} and give a verdict on whether we should allow it or not. Base your answer on phishing, impersonation, malware delivery, suspicious hosting, typosquatting, and social-engineering indicators.`;

  const upstream = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json',
      'http-referer': 'https://threatintel.ps191240.workers.dev',
      'x-title': 'Threat Intel Worker',
    },
    body: JSON.stringify({
      model,
      max_tokens,
      temperature,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
    }),
  });

  const payload = await upstream.json();
  if (!upstream.ok) {
    return jsonResponse({ error: payload?.error?.message || `OpenRouter HTTP ${upstream.status}`, upstream: payload }, upstream.status);
  }

  const content = payload?.choices?.[0]?.message?.content?.trim();
  if (!content) {
    return jsonResponse({ error: 'OpenRouter returned an empty response', upstream: payload }, 502);
  }

  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    return jsonResponse({ error: 'OpenRouter response was not valid JSON', raw: content, upstream: payload }, 502);
  }

  const normalizedVerdict = normalizeVerdict(parsed.verdict);
  return jsonResponse({
    verdict: normalizedVerdict,
    confidence: clampConfidence(parsed.confidence),
    summary: String(parsed.summary || '').trim(),
    reasons: Array.isArray(parsed.reasons) ? parsed.reasons.map((reason) => String(reason)) : [],
    raw: payload,
  });
}

function normalizeVerdict(verdict) {
  const value = String(verdict || '').toLowerCase().trim();
  if (value === 'allow') return 'allow';
  if (value === 'block') return 'block';
  return 'review';
}

function clampConfidence(value) {
  const num = Number.parseInt(value, 10);
  if (Number.isNaN(num)) return 50;
  return Math.max(0, Math.min(100, num));
}

async function passThroughResponse(upstream) {
  const text = await upstream.text();
  const contentType = upstream.headers.get('content-type') || 'application/json; charset=utf-8';
  return new Response(text, {
    status: upstream.status,
    headers: {
      ...JSON_HEADERS,
      'content-type': contentType,
    },
  });
}
