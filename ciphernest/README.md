# 🪺 CipherNest — Local Encrypted File Storage

Zero-knowledge local file hosting with **AES-256-GCM** encryption.
The server **never** stores or sees plaintext — all files are encrypted before disk writes.

---

## Quick Start

```bash
# 1. Install dependencies (only needed once)
npm install

# 2. Start the server
node server.js

# 3. Open browser
open http://localhost:3000
```

---

## Security Architecture

| Feature | Detail |
|---|---|
| **Cipher** | AES-256-GCM (authenticated encryption) |
| **Key Derivation** | PBKDF2-SHA256, 310,000 iterations |
| **IV** | 96-bit random per file |
| **Salt** | 256-bit random per file |
| **Auth Tag** | 128-bit GCM integrity check |
| **Network** | Bound to 127.0.0.1 — no external access |

### Encrypted file format (on disk):

```
[salt: 32 bytes][iv: 12 bytes][authTag: 16 bytes][ciphertext: variable]
```

### What CipherNest stores:
- ✅ Encrypted ciphertext only
- ✅ File metadata (name, size, type, date) — in `ciphernest_meta.json`
- ❌ Never the password
- ❌ Never the plaintext

---

## Threat Model

**Protected against:**
- Anyone with access to your disk (files are encrypted at rest)
- Network sniffers (server only binds to localhost)
- Tampering (GCM auth tag detects modification)

**Not protected against:**
- Someone who has your password AND your encrypted files
- Malware already running on your machine (inherent limitation of local storage)
- Weak passwords (use a strong one — the strength indicator helps)

---

## File Structure

```
ciphernest/
├── server.js                # Express server + crypto logic
├── public/
│   └── index.html           # Web UI
├── uploads/                 # Encrypted .enc files (auto-created)
├── ciphernest_meta.json     # File metadata (auto-created)
└── package.json
```

---

## Tips

- Use a **long passphrase** (16+ chars with mixed characters)
- Different passwords for different sensitivity levels
- `ciphernest_meta.json` only stores filenames/sizes — not content
- To wipe everything: delete `uploads/` and `ciphernest_meta.json`
