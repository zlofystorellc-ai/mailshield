// zod request schemas, shared by routes.
const { z } = require('zod');

const CATEGORIES = ['fake_payment_credit', 'kyc_bank_update', 'lottery_prize', 'fake_job', 'otp_request', 'fake_invoice',
  'delivery_scam', 'tech_support', 'impersonation', 'other'];

const domain = z.string().trim().toLowerCase().max(253)
  .regex(/^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/, 'invalid domain');

const localReason = z.object({
  id: z.string().max(64),
  weight: z.number().min(0).max(100).optional(),
  reason: z.string().max(500).optional(),
  reasonHi: z.string().max(500).optional(),
  harmType: z.string().max(64).optional(),
});

const register = z.object({ installId: z.string().uuid() });

const scan = z.object({
  senderEmail: z.string().max(320).default(''),
  senderName: z.string().max(200).default(''),
  subject: z.string().max(1000).default(''),
  urls: z.array(z.string().max(2048)).max(50).default([]),
  attachmentNames: z.array(z.string().max(255)).max(30).default([]),
  textFeatures: z.record(z.union([z.boolean(), z.number(), z.string().max(100)])).default({}),
  normalizedSnippet: z.string().max(2000).default(''),
  localScore: z.number().min(0).max(100).default(0),
  localReasons: z.array(localReason).max(40).default([]),
});

const feedback = z.object({
  scanId: z.string().regex(/^[a-f0-9]{24}$/),
  type: z.enum(['false_positive', 'true_positive']),
  comment: z.string().max(1000).optional().default(''),
});

const report = z.object({
  consent: z.literal(true),
  category: z.enum(CATEGORIES),
  comment: z.string().max(1000).optional().default(''),
  senderEmail: z.string().max(320).default(''),
  senderName: z.string().max(200).default(''),
  subject: z.string().max(1000).default(''), // already redacted client-side
  body: z.string().max(20000).default(''), // already redacted client-side
  urls: z.array(z.string().max(2048)).max(50).default([]),
  attachmentNames: z.array(z.string().max(255)).max(30).default([]),
  scanId: z.string().regex(/^[a-f0-9]{24}$/).optional(),
});

const override = z.object({
  scanId: z.string().regex(/^[a-f0-9]{24}$/).optional(),
  url: z.string().max(2048),
  score: z.number().min(0).max(100),
});

const listEntry = z.object({ domain });

const settings = z.object({
  language: z.enum(['en', 'hi']).optional(),
  aiEnabled: z.boolean().optional(),
});

const sigQuery = z.object({ sinceVersion: z.coerce.number().int().min(0).default(0) });

module.exports = { CATEGORIES, domain, register, scan, feedback, report, override, listEntry, settings, sigQuery, z };
