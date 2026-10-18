'use strict';

const crypto = require('crypto');

/**
 * Express middleware that verifies HMAC-SHA256 signature on incoming requests.
 * Expects the raw body to be available as `req.rawBody` (set by bodyParser.json with verify callback).
 * Compares `x-webhook-signature` header against computed HMAC using AI_WEBHOOK_SECRET.
 */
function verifyHmac(req, res, next) {
  const secret = process.env.AI_WEBHOOK_SECRET;
  if (!secret) {
    console.error('[hmac] AI_WEBHOOK_SECRET not configured');
    return res.status(500).json({ error: 'Server misconfiguration' });
  }

  const signature = req.headers['x-webhook-signature'];
  if (!signature) {
    return res.status(401).json({ error: 'Missing signature' });
  }

  const rawBody = req.rawBody;
  if (!rawBody) {
    return res.status(400).json({ error: 'Missing request body' });
  }

  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const sigBuffer = Buffer.from(signature, 'hex');
  const expBuffer = Buffer.from(expected, 'hex');

  if (sigBuffer.length !== expBuffer.length || !crypto.timingSafeEqual(sigBuffer, expBuffer)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  next();
}

module.exports = { verifyHmac };
