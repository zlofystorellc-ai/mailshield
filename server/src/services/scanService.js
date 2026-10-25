/*
 * POST /api/scan pipeline (spec §4):
 * 1 user lists -> 2 global blocklist -> 3/4 URL reputation (cache, Safe Browsing, VirusTotal, URLhaus)
 * -> 5 RDAP domain age -> 6 scam signatures -> 7 optional LLM -> 8 weighted combine.
 * Stores only features + hashes. External steps are time-boxed; on timeout they are skipped.
 */
const config = require('../config');
const { Scan, UserList, GlobalBlocklist } = require('../models');
const MS = require('../shared');
const reputation = require('./reputation');
const signatureService = require('./signatureService');
const { embed } = require('./embeddings');
const llm = require('./llm');
const verified = require('./verified');
const { combine } = require('./scoring');

const withTimeout = (p, ms, fallback) => Promise.race([
  p.catch(() => fallback),
  new Promise((resolve) => setTimeout(() => resolve(fallback), ms)),
]);

function finding(id, weight, reason, reasonHi, harmType, hard = false) {
  return { id, weight, reason, reasonHi, harmType, hard };
}

async function listFindings(user, senderEmail, senderDomain, urlDomains, simhash) {
  const entries = await UserList.find({ userId: user._id }).lean();
  const allow = entries.filter((e) => e.type === 'allow');
  const block = entries.filter((e) => e.type === 'block');
  if (allow.some((e) => e.domain === senderDomain || e.email === senderEmail)) return { allowlisted: true, findings: [] };

  const findings = [];
  const hit = block.find((e) => (e.domain && (e.domain === senderDomain || urlDomains.includes(e.domain))) || (e.email && e.email === senderEmail));
  if (hit) {
    const what = hit.domain || hit.email;
    findings.push(finding('user_blocklist', 100, `You blocked "${what}" earlier.`, `Aapne "${what}" ko pehle block kiya tha.`, 'other', true));
  }
  if (block.some((e) => e.simhash && MS.simhash.hamming(e.simhash, simhash) <= config.learning.simhashDistance)) {
    findings.push(finding('reported_before', 40, 'You reported a very similar message as a scam before.',
      'Aapne pehle bhi aise hi message ko scam report kiya tha.', 'other'));
  }
  return { allowlisted: false, findings };
}

function reputationFindings(results) {
  const out = [];
  for (const r of results) {
    const sb = r.sources && r.sources.safeBrowsing;
    const uh = r.sources && r.sources.urlhaus;
    const vt = r.sources && r.sources.virusTotal;
    if (sb && sb.threat) {
      const malware = /MALWARE|UNWANTED|HARMFUL/.test(sb.threat);
      out.push(finding('safe_browsing', 60, `Google Safe Browsing lists ${r.domain} as ${malware ? 'malware' : 'phishing'}.`,
        `Google Safe Browsing ne ${r.domain} ko ${malware ? 'malware' : 'phishing'} bataya hai.`, malware ? 'malware' : 'credential_phishing', true));
    }
    if (uh && uh.listed) {
      out.push(finding('urlhaus', 60, `${r.domain} is a known malware distribution site (URLhaus).`,
        `${r.domain} ek jaani-maani malware site hai (URLhaus).`, 'malware', true));
    }
    if (vt && vt.malicious >= 3) {
      out.push(finding('virustotal_malicious', 50, `${vt.malicious} security vendors flag ${r.domain} as malicious (VirusTotal).`,
        `${vt.malicious} security vendors ne ${r.domain} ko khatarnaak bataya hai (VirusTotal).`, 'credential_phishing', true));
    } else if (vt && (vt.malicious >= 1 || vt.suspicious >= 3)) {
      out.push(finding('virustotal_suspicious', 20, `Some security vendors flag ${r.domain} as suspicious (VirusTotal).`,
        `Kuch security vendors ne ${r.domain} ko suspicious bataya hai.`, 'credential_phishing'));
    }
    if (r.domainAgeDays != null && r.domainAgeDays < 30) {
      out.push(finding('new_domain', r.domainAgeDays < 7 ? 30 : 20, `The website ${r.domain} was registered only ${r.domainAgeDays} day(s) ago.`,
        `Website ${r.domain} sirf ${r.domainAgeDays} din pehle bani hai.`, 'credential_phishing'));
    }
  }
  // one finding per id (highest weight)
  const best = new Map();
  out.forEach((f) => { if (!best.has(f.id) || best.get(f.id).weight < f.weight) best.set(f.id, f); });
  return [...best.values()];
}

async function scan(user, body) {
  const senderEmail = String(body.senderEmail || '').toLowerCase();
  const senderDomain = MS.brands.registrable(MS.brands.domainOfEmail(senderEmail));
  const urls = body.urls.filter((u) => /^https?:\/\//i.test(u));
  const urlDomains = [...new Set(urls.map((u) => { try { return MS.brands.registrable(new URL(u).hostname); } catch (e) { return null; } }).filter(Boolean))];
  const normalized = MS.normalize.normalizeText(body.normalizedSnippet, { max: MS.normalize.MAX_MATCH_CHARS });
  const simhash = MS.simhash.simhash(normalized);
  const localReasons = body.localReasons.map((r) => ({ ...r, weight: r.weight || 0 }));

  const [lists, globalHits, isVerified, embedding] = await Promise.all([
    listFindings(user, senderEmail, senderDomain, urlDomains, simhash),
    GlobalBlocklist.find({ domain: { $in: [senderDomain, ...urlDomains].filter(Boolean) } }).lean(),
    verified.isVerified(senderDomain),
    withTimeout(embed(normalized), config.externalTimeoutMs, null),
  ]);

  let result;
  let matchedSignatureId = null;
  if (lists.allowlisted) {
    result = { score: 0, level: 'safe', reasons: [], harms: [], threatType: null };
  } else {
    const findings = [...lists.findings];
    globalHits.forEach((g) => findings.push(finding('global_blocklist', 80, `${g.domain} is on MailShield's global scam blocklist.`,
      `${g.domain} MailShield ki global scam blocklist mein hai.`, 'credential_phishing', true)));

    const [rep, sigMatch] = await Promise.all([
      withTimeout(reputation.checkUrls(urls), config.externalTimeoutMs + 1000, []),
      isVerified ? null : signatureService.match({ normalized, simhash, embedding, senderDomain, urlDomains }).catch(() => null),
    ]);
    findings.push(...reputationFindings(rep));

    if (sigMatch) {
      const sig = sigMatch.signature;
      matchedSignatureId = sig.signatureId;
      const label = MS.harms.CATEGORIES[sig.category] || MS.harms.CATEGORIES.other;
      findings.push(finding('signature_match', config.learning.signatureMatchBoost,
        `Similar to a ${label.en} scam reported by ${sig.distinctUsers} users. ${(sig.reasonText && sig.reasonText.en) || ''}`.trim(),
        `${sig.distinctUsers} users ne aise hi ${label.hi} scam ki report ki hai. ${(sig.reasonText && sig.reasonText.hinglish) || ''}`.trim(),
        sig.threatType || 'other'));
    }

    // LLM only for the uncertain middle band, only if the user opted in, never for verified senders.
    const preScore = body.localScore + findings.reduce((s, f) => s + f.weight, 0);
    if (user.settings && user.settings.aiEnabled && llm.enabled() && !isVerified && preScore >= 15 && preScore < 70) {
      const ai = await withTimeout(llm.classifyEmail({ senderDomain, subjectNormalized: '', normalizedSnippet: normalized, urlDomains }), 9000, null);
      if (ai && ai.isScam && ai.confidence >= 0.6) {
        findings.push(finding('ai_classifier', Math.round(30 * ai.confidence), `AI analysis: ${ai.reason || 'this looks like a scam.'}`,
          `AI analysis: yeh scam jaisa lagta hai. ${ai.reason || ''}`.trim(), ai.threatType));
      }
    }

    result = combine({
      localScore: body.localScore, localReasons, serverFindings: findings,
      verifiedSender: isVerified, signatureMatched: !!sigMatch,
    });
  }

  const doc = await Scan.create({
    userId: user._id,
    senderDomain,
    subjectHash: reputation.sha256(String(body.subject || '').toLowerCase().trim()),
    simhash,
    urls: urls.slice(0, 50).map((u) => { let d = ''; try { d = new URL(u).hostname; } catch (e) { /* skip */ } return { domain: d, sha256: reputation.sha256(u) }; }),
    score: result.score,
    level: result.level,
    reasons: result.reasons.map((r) => r.id),
    threatType: result.threatType,
    matchedSignatureId,
  });

  return { scanId: String(doc._id), ...result, matchedSignatureId };
}

module.exports = { scan, reputationFindings };
