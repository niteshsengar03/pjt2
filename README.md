# Schnorr ZKP Authentication Demo

A minimal demo showing **passwordless authentication using Schnorr Zero-Knowledge Proof (ZKP)**.

The client proves ownership of a secret key without ever sending the secret to the server.

---

## ⚙️ Tech Stack

- React + Vite (Frontend)
- Express (Backend)
- TypeScript
- Web Crypto API (AES-GCM + PBKDF2)
- BigInt modular arithmetic

---

## 🧠 Concept

### Signup
1. Client generates:
   - Private key `x`
   - Public key `P = g^x mod p`
2. Private key is encrypted locally using a passphrase.
3. Only the **public key** is sent to the server.

### Login (Schnorr ZKP)
1. Client creates commitment:

