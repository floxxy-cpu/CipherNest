# CipherNest — Local Encrypted File Storage

Local file hosting server with enterprise-grade encryption.
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

### Encrypted file format (on disk):

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
- Some strong malware. (It is recommended to run a full virus scan with Malwarebytes monthly)
- Weak passwords (use a strong one — the strength indicator helps)

## Tips

- Use a **long passphrase** (16+ chars with mixed characters)
- Different passwords for different sensitivity levels
- `ciphernest_meta.json` only stores filenames/sizes — not content
- To wipe everything: delete `uploads/` and `ciphernest_meta.json`
