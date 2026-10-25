// Loads the shared engine in dependency order and returns the MailShield namespace.
['brands', 'redact', 'normalize', 'simhash', 'harms', 'signatures', 'heuristics'].forEach((m) => require('./' + m));

module.exports = globalThis.MailShield;
