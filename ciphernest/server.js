const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const META_FILE = path.join(__dirname, 'ciphernest_meta.json');

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- Crypto Helpers ---

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256');
}

function encryptFile(buffer, password) {
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(password, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Layout: [salt(32)][iv(12)][authTag(16)][ciphertext]
  return Buffer.concat([salt, iv, authTag, encrypted]);
}

function decryptFile(buffer, password) {
  const salt = buffer.slice(0, 32);
  const iv = buffer.slice(32, 44);
  const authTag = buffer.slice(44, 60);
  const ciphertext = buffer.slice(60);
  const key = deriveKey(password, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// --- Metadata Store ---

function loadMeta() {
  if (!fs.existsSync(META_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(META_FILE, 'utf8')); }
  catch { return {}; }
}

function saveMeta(meta) {
  fs.writeFileSync(META_FILE, JSON.stringify(meta, null, 2));
}

// --- Routes ---

// Upload file
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

app.post('/api/upload', upload.single('file'), (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password required' });
    if (!req.file) return res.status(400).json({ error: 'No file provided' });

    const fileId = crypto.randomUUID();
    const encryptedBuffer = encryptFile(req.file.buffer, password);
    const encryptedPath = path.join(UPLOADS_DIR, fileId + '.enc');
    fs.writeFileSync(encryptedPath, encryptedBuffer);

    const meta = loadMeta();
    meta[fileId] = {
      id: fileId,
      originalName: req.file.originalname,
      mimeType: req.file.mimetype,
      size: req.file.size,
      uploadedAt: new Date().toISOString(),
      encryptedSize: encryptedBuffer.length
    };
    saveMeta(meta);

    res.json({ success: true, fileId, name: req.file.originalname, size: req.file.size });
  } catch (err) {
    res.status(500).json({ error: 'Upload failed: ' + err.message });
  }
});

// List files
app.get('/api/files', (req, res) => {
  const meta = loadMeta();
  const files = Object.values(meta).sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
  res.json(files);
});

// Download (decrypt) file
app.post('/api/download/:fileId', (req, res) => {
  try {
    const { fileId } = req.params;
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password required' });

    const meta = loadMeta();
    const fileMeta = meta[fileId];
    if (!fileMeta) return res.status(404).json({ error: 'File not found' });

    const encryptedPath = path.join(UPLOADS_DIR, fileId + '.enc');
    if (!fs.existsSync(encryptedPath)) return res.status(404).json({ error: 'Encrypted file missing' });

    const encryptedBuffer = fs.readFileSync(encryptedPath);
    let decrypted;
    try {
      decrypted = decryptFile(encryptedBuffer, password);
    } catch {
      return res.status(401).json({ error: 'Wrong password or corrupted file' });
    }

    res.setHeader('Content-Type', fileMeta.mimeType || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fileMeta.originalName)}"`);
    res.send(decrypted);
  } catch (err) {
    res.status(500).json({ error: 'Download failed: ' + err.message });
  }
});

// Delete file
app.delete('/api/files/:fileId', (req, res) => {
  try {
    const { fileId } = req.params;
    const meta = loadMeta();
    if (!meta[fileId]) return res.status(404).json({ error: 'File not found' });

    const encryptedPath = path.join(UPLOADS_DIR, fileId + '.enc');
    if (fs.existsSync(encryptedPath)) fs.unlinkSync(encryptedPath);

    delete meta[fileId];
    saveMeta(meta);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed: ' + err.message });
  }
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`\n🪺  CipherNest running at http://localhost:${PORT}`);
  console.log(`   Bound to 127.0.0.1 only — no external access\n`);
});
