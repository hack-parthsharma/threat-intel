# TRISHUL threat intelligence

The original repository contains a single static `index.html`. It implements URL
checks, sequential bulk URL scans, browser-side file analysis, external file scan
providers, SIA control assessments, history, exports, and Teams notifications.
The browser calls `PROXY_BASE`, a separate Cloudflare Worker. This change adds
that Worker from the supplied v4.0 source so the frontend and backend can be
reviewed and maintained together.

## URL verdict fix

Previously `/api/openrouter-security-check` sent only the URL to an LLM, requested
an ALLOW/BLOCK decision from model knowledge, and guessed a verdict by looking
for the word `block` if JSON parsing failed. The randomly routed free model had
no current threat evidence. The browser also interpreted any non-ALLOW result
as BLOCK and displayed model text as HTML.

The endpoint now collects its own URL reputation evidence, independently of
browser-submitted results. It queries the **exact URL** in VirusTotal, URLhaus,
and PhishTank. A domain report does not approve every path on that domain.
It never fetches the target page or submits a new VirusTotal scan.

| Verdict | Policy v1 |
| --- | --- |
| BLOCK | At least 3 malicious vendors in a VirusTotal URL report no older than 24 hours, an online URLhaus malware listing, or verified and valid PhishTank phishing. |
| ALLOW | VirusTotal URL report within 24 hours, at least 10 harmless vendors, no malicious/suspicious vendors, both blocklists return not-listed, and no structural/redirect concern. |
| REVIEW | Every other case, including failures, missing keys, stale reports, isolated detections, unsupported evidence and unverified listings. |

These are explicit conservative policy thresholds, **not measured accuracy
guarantees**. Confidence describes the evidence supporting the policy decision;
it is not a calibrated probability. ALLOW never claims universal safety. A report
can miss a new compromise, client-side behavior, geotargeting, or a later redirect.
Fresh exact-URL reports may be absent for legitimate sites, which results in REVIEW.

URL keywords, hyphens, popularity, country, and a trusted-domain list do not decide
this verdict. A URL fragment, credential-bearing URL, IP hostname, IDN, HTTP,
nonstandard port or reported redirect requires review unless blocking evidence
already exists. Credentials are not sent to reputation providers by this endpoint.
URL query strings are sent to those providers as part of an exact-URL lookup.

Optional AI only orders the evidence findings. It must return a permutation of
existing finding IDs. It cannot invent claims or change the decision, confidence,
or recommendation. Missing, invalid, or failed AI responses leave the evidence
assessment intact. The card discloses whether AI prioritization was used.

The existing auxiliary engine cards and their numerical heuristic scores remain
diagnostic signals, not calibrated safety estimates. The final URL verdict and
history/bulk classification come from the new policy. SIA/file assessment logic
is outside this change. Existing automatic Teams notifications are retained;
no notification was sent during development or testing.

## Files and local verification

- `index.html`: static UI, URL/bulk checks and SIA.
- `worker.js`: complete standalone Worker, ready for Cloudflare's editor.
- `url-verdict.js`: maintainable source for the new policy and adapters.
- `scripts/build-worker.mjs`: embeds that module into `worker.js` without imports.
- `test/url-verdict.test.js`: Node test runner regression tests; no dependencies.

Use Node 20 or later:

```sh
npm run build
npm test
```

Run the build after editing `url-verdict.js` and commit the generated Worker too.
The tests cover provider failures, stale/future reports, isolated detections,
historical/unverified listings, redirects, credential-bearing URLs, malformed AI,
exact-URL encoding, input validation, Worker routes, and escaped REVIEW rendering.

The supplied `https://brtx-f1-uc.bswa.net/` is a regression input with **mocked**
provider evidence. It is not allowlisted and the tests do not establish its live
safety. The live reputation request from the development environment failed.

## Deploy to the existing Worker

1. Rotate the VirusTotal API key previously embedded in public `index.html`.
   Removing it from the current HTML does not remove it from Git history.
2. In the existing Cloudflare Worker, retain existing bindings and secrets.
   Configure `VT_API_KEY` and `URLHAUS_AUTH_KEY` as secrets. `PHISHTANK_APP_KEY`
   is optional but improves lookup rate limits. Missing/failed providers give REVIEW.
3. For optional AI prioritization, set secret `OPENROUTER_API_KEY` and server-side
   variable `OPENROUTER_MODEL` to a specific model available to your account.
   No model is selected by the client. Without both values, the evidence verdict
   still works and AI prioritization is skipped.
4. Replace the existing Worker code with the complete `worker.js`, then deploy.
   No bundler or import resolution is needed for this file. Other routes and their
   existing secrets are retained from the supplied Worker.
5. Publish the updated `index.html` through the existing frontend hosting process.
   Confirm `PROXY_BASE` points to that Worker. Deploy the Worker first; the new UI
   rejects old verdicts without `policy_version: "url-evidence-v1"` and shows REVIEW.
6. Check a known current detection, a recent clean report and an unknown URL in
   the live deployment. Check bulk mode as well. Actual source coverage depends
   on your credentials and provider rate limits. Each assessment uses up to three
   reputation lookups and, if configured, one AI request; auxiliary UI engine
   lookups are additional. Requests have an 8-second timeout per provider.

This change has not been deployed to Cloudflare. No production keys were used
in the test suite. Existing Worker authentication (`INTERNAL_API_KEY`) is retained;
do not put that key into static frontend code. If enabled, the frontend needs an
authenticated gateway rather than a public embedded shared secret.

## Provider references

- [VirusTotal URL identifiers](https://docs.virustotal.com/reference/url)
- [VirusTotal URL fields and analysis timestamps](https://docs.virustotal.com/reference/url-object)
- [URLhaus authenticated lookup example](https://github.com/abusech/URLhaus/blob/master/lookup_url.py)
- [PhishTank response fields and rate limits](https://phishtank.org/api_info.php)
