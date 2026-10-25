/*
 * All Mongoose schemas (spec §7). Collection names are set explicitly to match the spec.
 * Atlas Vector Search indexes are NOT created here — see README "Atlas Vector Search".
 */
const { Schema, model, Types } = require('mongoose');

const ObjectId = Schema.Types.ObjectId;
const LEVELS = ['safe', 'warning', 'block'];

// ---- users ----
const User = model('User', new Schema({
  installId: { type: String, required: true, unique: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  settings: {
    language: { type: String, enum: ['en', 'hi'], default: 'en' },
    aiEnabled: { type: Boolean, default: false },
  },
  createdAt: { type: Date, default: Date.now },
}), 'users');

// ---- scans (features + hashes only; never the body). TTL 90 days ----
const Scan = model('Scan', new Schema({
  userId: { type: ObjectId, ref: 'User', index: true },
  senderDomain: { type: String, index: true },
  subjectHash: String,
  simhash: String,
  urls: [{ _id: false, domain: String, sha256: String }],
  score: Number,
  level: { type: String, enum: LEVELS, index: true },
  reasons: [String],
  threatType: String,
  matchedSignatureId: { type: String, index: true },
  createdAt: { type: Date, default: Date.now, expires: '90d' },
}), 'scans');

// ---- url reputation cache. TTL 24h ----
const UrlReputation = model('UrlReputation', new Schema({
  urlHash: { type: String, required: true, unique: true },
  domain: { type: String, index: true },
  sources: {
    safeBrowsing: Schema.Types.Mixed,
    virusTotal: Schema.Types.Mixed,
    urlhaus: Schema.Types.Mixed,
  },
  domainAgeDays: Number,
  verdict: { type: String, enum: ['clean', 'suspicious', 'malicious', 'unknown'], default: 'unknown' },
  checkedAt: { type: Date, default: Date.now, expires: '24h' },
}), 'url_reputation');

// ---- feedback ----
const Feedback = model('Feedback', new Schema({
  scanId: { type: ObjectId, ref: 'Scan', index: true },
  userId: { type: ObjectId, ref: 'User', index: true },
  signatureId: { type: String, index: true },
  type: { type: String, enum: ['false_positive', 'true_positive'], required: true },
  comment: { type: String, maxlength: 1000 },
  createdAt: { type: Date, default: Date.now },
  reviewed: { type: Boolean, default: false, index: true },
}), 'feedback');

// ---- overrides ("open anyway") ----
const Override = model('Override', new Schema({
  scanId: { type: ObjectId, ref: 'Scan' },
  userId: { type: ObjectId, ref: 'User', index: true },
  urlDomain: { type: String, index: true },
  score: Number,
  createdAt: { type: Date, default: Date.now },
}), 'overrides');

// ---- per-user allow/block lists ----
const userListSchema = new Schema({
  userId: { type: ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['allow', 'block'], required: true },
  domain: String, // registrable domain
  email: String, // exact sender address (used for free-mail senders)
  signatureId: String, // a signature the user blocked
  simhash: String, // a template the user reported (personal match before global activation)
  createdAt: { type: Date, default: Date.now },
});
userListSchema.index({ userId: 1, type: 1 });
const UserList = model('UserList', userListSchema, 'user_lists');

// ---- global blocklist ----
const GlobalBlocklist = model('GlobalBlocklist', new Schema({
  domain: { type: String, required: true, unique: true },
  reportCount: { type: Number, default: 0 },
  approvedBy: String,
  createdAt: { type: Date, default: Date.now },
}), 'global_blocklist');

// ---- user-reported messages (redacted, consented) ----
const reportedSchema = new Schema({
  userId: { type: ObjectId, ref: 'User', index: true },
  category: { type: String, required: true },
  comment: { type: String, maxlength: 1000 },
  senderDomain: { type: String, index: true },
  senderName: String,
  redactedSubject: String,
  redactedBody: String,
  normalizedText: String,
  simhash: { type: String, index: true },
  embedding: { type: [Number], default: undefined },
  urls: [String],
  urlDomains: [String],
  attachmentNames: [String],
  clusterId: { type: String, index: true },
  status: { type: String, enum: ['new', 'clustered', 'confirmed', 'rejected'], default: 'new', index: true },
  heldForAdmin: { type: Boolean, default: false }, // e.g. verified sender — never auto-processed
  lockedAt: Date, // worker claim
  error: String,
  createdAt: { type: Date, default: Date.now, index: true },
});
const ReportedMessage = model('ReportedMessage', reportedSchema, 'reported_messages');

// ---- scam signatures ----
const sigSchema = new Schema({
  signatureId: { type: String, required: true, unique: true },
  clusterId: { type: String, index: true },
  category: String,
  threatType: String,
  simhash: String,
  centroidEmbedding: { type: [Number], default: undefined },
  keywords: [String],
  senderDomains: [String],
  urlDomains: [String],
  reportCount: { type: Number, default: 0 },
  distinctUsers: { type: Number, default: 0 },
  falseAlarmCount: { type: Number, default: 0 },
  confidence: { type: Number, default: 0.5 },
  status: { type: String, enum: ['pending_review', 'active', 'rejected'], default: 'pending_review', index: true },
  adminLocked: { type: Boolean, default: false }, // admin decided; automation won't flip status
  version: { type: Number, default: 0, index: true },
  reasonText: { en: String, hinglish: String },
  suggestedKeywords: [String],
}, { timestamps: true });
const ScamSignature = model('ScamSignature', sigSchema, 'scam_signatures');

// ---- reporter trust ----
const ReporterTrust = model('ReporterTrust', new Schema({
  userId: { type: ObjectId, ref: 'User', unique: true },
  confirmedReports: { type: Number, default: 0 },
  rejectedReports: { type: Number, default: 0 },
  trustScore: { type: Number, default: 1.0 },
}), 'reporter_trust');

// ---- verified legit senders (never auto-blocked) ----
const VerifiedSender = model('VerifiedSender', new Schema({
  domain: { type: String, required: true, unique: true },
  organization: String,
  addedBy: String,
}), 'verified_senders');

// ---- small key/value store (global signature version) ----
const Meta = model('Meta', new Schema({
  key: { type: String, unique: true },
  value: Schema.Types.Mixed,
}), 'meta');

module.exports = {
  Types, User, Scan, UrlReputation, Feedback, Override, UserList, GlobalBlocklist,
  ReportedMessage, ScamSignature, ReporterTrust, VerifiedSender, Meta,
};
