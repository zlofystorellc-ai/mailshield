/*
 * Pluggable text embeddings. EMBEDDING_PROVIDER:
 *   local  - hashed bag-of-concepts (no network, 256 dims by default)
 *   openai - OpenAI embeddings API (EMBEDDING_MODEL, EMBEDDING_DIM)
 * Returns null on provider failure; callers then fall back to SimHash + keywords.
 * NOTE: the Atlas index numDimensions must equal EMBEDDING_DIM. Don't mix providers in one DB.
 */
const config = require('../config');
const { fetchJson } = require('./http');
const MS = require('../shared');

async function embed(normalizedText) {
  const { provider, apiKey, model, dim } = config.embedding;
  if (!normalizedText) return null;
  if (provider === 'local') return MS.simhash.localEmbedding(normalizedText, dim);

  if (provider === 'openai') {
    if (!apiKey) return null;
    const r = await fetchJson('https://api.openai.com/v1/embeddings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ model, input: normalizedText.slice(0, 6000), dimensions: dim }),
    }, 8000);
    const v = r.ok && r.data && r.data.data && r.data.data[0] && r.data.data[0].embedding;
    return Array.isArray(v) ? v : null;
  }
  return null;
}

module.exports = { embed };
