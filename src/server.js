require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { extractToPdfBuffer, inspectDocumentInfo } = require('./extractor');

const app = express();
const PORT = process.env.PORT || 3000;
const WORKER_SECRET = process.env.WORKER_SECRET || '';

// ─── Replica Identity ─────────────────────────────────
// RAILWAY_REPLICA_ID is unique per replica; RAILWAY_DEPLOYMENT_ID is shared.
const REPLICA_ID = process.env.RAILWAY_REPLICA_ID || 'local';
const tag = `[replica ${REPLICA_ID}]`;

// ─── Security ────────────────────────────────────────
app.use(helmet());
app.set('trust proxy', 1);

// Only your base VPS should be calling this — no public CORS needed
app.use(cors({ origin: false }));

// ─── Rate limit: guard against unauthenticated hammering ────────────
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    skip: (req) => {
      const provided = req.headers['x-worker-secret'] || req.body?.secret;
      return (
        process.env.NODE_ENV !== 'production' ||
        (WORKER_SECRET && provided === WORKER_SECRET) ||
        req.ip === '127.0.0.1' ||
        req.ip === '::1' ||
        req.ip === '::ffff:127.0.0.1'
      );
    },
    message: { success: false, message: 'Too many requests.' },
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use(express.json({ limit: '10mb' }));

// ─── Auth middleware ─────────────────────────────────
function requireSecret(req, res, next) {
  const provided = req.headers['x-worker-secret'] || req.body?.secret;
  if (!WORKER_SECRET || provided !== WORKER_SECRET) {
    return res.status(401).json({ success: false, message: 'Unauthorized.' });
  }
  next();
}

// ─── Worker Concurrency & Busy State ────────────────
// Enforce rule: 1 worker should get only one part at a time
let isExtracting = false;
let currentJobInfo = null;

// ─── Health check (public, no auth) ─────────────────
app.get('/health', (req, res) => {
  const fs = require('fs');
  const os = require('os');
  res.json({
    status: 'ok',
    busy: isExtracting,
    currentJob: currentJobInfo,
    replica: REPLICA_ID,
    worker: process.env.WORKER_ID || 'scribdly-worker',
    uptime: Math.round(process.uptime()),
    user: os.userInfo ? os.userInfo().username : 'unknown',
    home: process.env.HOME,
    chromePath: process.env.CHROME_PATH,
    chromeExists: fs.existsSync('/usr/bin/google-chrome-stable'),
  });
});

// ─── Fast Document Metadata Inspection ───────────────
/**
 * POST /inspect
 * Returns totalPages in 1-2 seconds without performing extraction.
 */
app.post('/inspect', requireSecret, async (req, res) => {
  const { documentId, html } = req.body;

  if (!documentId || !/^\d+$/.test(String(documentId).trim())) {
    return res.status(400).json({
      success: false,
      message: 'documentId must be a numeric Scribd document ID.',
    });
  }

  try {
    const info = await inspectDocumentInfo(String(documentId), html || null);
    res.status(200).json({ success: true, ...info });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── Main extraction endpoint ────────────────────────
/**
 * POST /extract
 * Headers: x-worker-secret: <WORKER_SECRET>
 * Body:    { documentId: "123456789" }
 *
 * Response: application/pdf binary on success
 *           application/json error on failure
 */
app.post('/extract', requireSecret, async (req, res) => {
  const { documentId, html, startPage, endPage } = req.body;

  if (!documentId || !/^\d+$/.test(String(documentId).trim())) {
    return res.status(400).json({
      success: false,
      message: 'documentId must be a numeric Scribd document ID.',
    });
  }

  const rangeStr = startPage || endPage ? ` [pages ${startPage || 1}..${endPage || 'end'}]` : '';

  // Strict concurrency guard: 1 worker gets only one part at a time
  if (isExtracting) {
    console.warn(
      `${tag} [Worker] ⛔ Rejected extraction for ${documentId}${rangeStr}: worker is already extracting ${currentJobInfo || 'another part'} (1 part at a time rule)`
    );
    return res.status(429).json({
      success: false,
      busy: true,
      message: `Worker replica ${REPLICA_ID} is currently busy processing ${currentJobInfo || 'another part'}. 1 part at a time only.`,
      replica: REPLICA_ID,
    });
  }

  isExtracting = true;
  currentJobInfo = `doc ${documentId}${rangeStr}`;

  console.log(
    `${tag} [Worker] Starting extraction for document ${documentId}${rangeStr}${html ? ' (with pre-resolved HTML)' : ''}`
  );
  const startedAt = Date.now();

  try {
    const result = await extractToPdfBuffer(String(documentId), html || null, startPage || null, endPage || null);

    const { pdfBuffer, totalPages, thumbnailUrl, startPage: fromP, endPage: toP, partPages } = result;

    const executionElapsed = ((Date.now() - startedAt) / 1000).toFixed(1);

    console.log(
      `${tag} [Worker] ✅ Extracted ${partPages || totalPages} pages (range ${fromP || 1}..${toP || totalPages}) in ${executionElapsed}s — ${pdfBuffer.length} bytes`
    );

    // Return PDF binary with metadata headers so the base VPS can read them
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Length', pdfBuffer.length);
    res.setHeader('X-Total-Pages', totalPages);
    res.setHeader('X-Start-Page', fromP || 1);
    res.setHeader('X-End-Page', toP || totalPages);
    res.setHeader('X-Part-Pages', partPages || totalPages);
    res.setHeader('X-Thumbnail-Url', thumbnailUrl || '');
    res.setHeader('X-Replica-Id', REPLICA_ID);
    res.setHeader('X-Elapsed-Seconds', executionElapsed);
    res.status(200).send(pdfBuffer);
  } catch (err) {
    const executionElapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
    console.error(
      `${tag} [Worker] ❌ Extraction failed for ${documentId} after ${executionElapsed}s:`,
      err.message
    );
    res.status(500).json({
      success: false,
      message: err.message || 'Extraction failed.',
      elapsed: executionElapsed,
      replica: REPLICA_ID,
    });
  } finally {
    isExtracting = false;
    currentJobInfo = null;
  }
});

// ─── 404 ─────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Not found.' });
});

// ─── Global error handler ────────────────────────────
app.use((err, req, res, next) => {
  console.error(`${tag} [Worker] Unhandled error:`, err.stack);
  res.status(500).json({ success: false, message: 'Internal error.' });
});

// ─── Start ───────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n👌🏿 Scribdly Worker running on port ${PORT}`);
  console.log(`   Replica ID: ${REPLICA_ID}`);
  console.log(`   Worker ID: ${process.env.WORKER_ID || 'scribdly-worker'}`);
  console.log(`   Chrome:    ${process.env.CHROME_PATH || 'auto-detect'}`);
  console.log(`   Secret:    ${WORKER_SECRET ? '✅ set' : '❌ NOT SET — worker is unprotected!'}\n`);
});

module.exports = app;

