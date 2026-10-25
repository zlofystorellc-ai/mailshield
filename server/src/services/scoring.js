/*
 * Pure scoring: merges the extension's local heuristic result with server-side evidence.
 * Kept free of I/O so it is unit-testable.
 */
const MS = require('../shared');

const { LEVELS, levelOf } = MS.heuristics;

/**
 * @param {object} p
 * @param {number} p.localScore
 * @param {Array<{id,weight,reason,reasonHi,harmType}>} p.localReasons
 * @param {Array<{id,weight,reason,reasonHi,harmType,hard?:boolean}>} p.serverFindings - hard=true for blocklist / SB / URLhaus hits
 * @param {boolean} p.verifiedSender
 * @param {boolean} p.signatureMatched
 */
function combine({ localScore = 0, localReasons = [], serverFindings = [], verifiedSender = false, signatureMatched = false }) {
  const localIds = new Set(localReasons.map((r) => r.id));
  // Don't double count: the extension may already have matched the same signature locally.
  const extras = serverFindings.filter((f) => !localIds.has(f.id));
  let score = Math.min(100, Math.max(0, localScore) + extras.reduce((s, f) => s + f.weight, 0));

  if (signatureMatched || localIds.has('signature_match')) score = Math.max(score, LEVELS.WARNING);

  const hard = serverFindings.some((f) => f.hard);
  if (verifiedSender && !hard) score = Math.min(score, 20); // verified legit senders can't be auto-escalated

  const reasons = [...localReasons, ...extras]
    .sort((a, b) => (b.weight || 0) - (a.weight || 0))
    .map((r) => ({ id: r.id, weight: r.weight || 0, en: r.reason || '', hi: r.reasonHi || r.reason || '', harmType: r.harmType || 'other' }));

  const typed = reasons.filter((r) => r.harmType && r.harmType !== 'other');
  const threatType = typed.length ? typed[0].harmType : reasons.length ? 'other' : null;
  const level = levelOf(score);
  const harms = level === 'safe' ? [] : MS.harms.harmsFor(reasons.map((r) => r.harmType));

  return { score, level, reasons: level === 'safe' && verifiedSender ? [] : reasons, threatType, harms };
}

module.exports = { combine, LEVELS, levelOf };
