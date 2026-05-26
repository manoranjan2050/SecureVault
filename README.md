# 🛡️ SecureVault (Elite Edition) v2.2.0

![Security Level](https://img.shields.io/badge/Security_Level-Extreme-red?style=for-the-badge&logo=shield)
![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-blue?style=for-the-badge)
![KDF](https://img.shields.io/badge/KDF-Argon2id-blueviolet?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Armed_&_Secure-green?style=for-the-badge)

**SecureVault** is a premium, portable, and zero-knowledge digital asset manager. Designed for high-stakes privacy, it combines bit-level military-grade encryption with a modern, glassmorphism-inspired UI to protect your most sensitive credentials and documents.

---

## 🚀 Elite Feature Suite

### 🔐 Multi-Tier Cryptography
*   **Bit-Level Sealing:** All data is encrypted using **AES-256-GCM** authenticated encryption.
*   **Fortified Key Derivation:** Employs **Argon2id** (the winner of the Password Hashing Competition) to derive keys, making brute-force attacks mathematically infeasible.
*   **Recovery Protocol Kit:** A fail-safe emergency system using an offline master key phrase to recover data if the master password is lost.

### ☁️ Triple-Cloud Redundancy
Secure your vault with one-click encrypted exports to global providers:
*   **Telegram Cloud:** Direct delivery to your private chat via a secure bot.
*   **GitHub Private Sync:** Version-controlled backups in your private repositories.
*   **Dropbox Direct:** Seamless synchronization to your personal cloud folders.

### 🛡️ Active System Defense
*   **🚨 Panic Mode Protocol:** A hidden emergency override that instantly moves all active data to the trash and locks the vault.
*   **👤 Privacy Shield:** Optional auto-lock protocol that triggers immediately when switching browser tabs or minimizing the window.
*   **🔗 Ephemeral Secret Sharing:** Create encrypted, self-destructing links to share sensitive notes without ever exposing them to a server.

### 📂 Advanced Data Architecture
*   **🔑 Password Manager:** Comprehensive storage with strength analytics and full revision history.
*   **🕒 Secure Authenticator:** Native TOTP support (2FA) with batch migration import from Google Authenticator.
*   **💼 Records Vault:** Specialized schemas for Finance, Bank Accounts, Insurance, and Crypto Wallets.
*   **📄 Document Cloud:** Bit-level encryption for PDFs and identification images with secure in-browser previews.
*   **📔 Secure Notes:** Encrypted long-form text storage for API keys, recovery seeds, and private thoughts.

---

## 🛠️ Technical Specifications

| Component | Technology |
| :--- | :--- |
| **Backend** | Python 3.10+, Flask, SQLite 3 |
| **Encryption** | Cryptography (AES-GCM), Argon2-cffi |
| **Frontend** | Tailwind CSS (Glassmorphism), Vanilla JS, Chart.js |
| **Protocols** | TOTP (RFC 6238), Google Migration Proto |
| **APIs** | Telegram Bot, GitHub v3, Dropbox v2 |

---

## 📦 Quick Start

### 🪟 Windows (Portable)
1.  **Download** the latest release.
2.  Double-click `start.bat`.
3.  Navigate to `http://127.0.0.1:5000` to initialize your Master Key.

### 🐧 Linux / macOS
1.  Open terminal in the folder.
2.  Run: `chmod +x start.sh && ./start.sh`
3.  Access the gateway at `http://127.0.0.1:5000`.

---

## 🛡️ Critical Security Mandate

SecureVault is a **Zero-Knowledge, Offline Local Vault**. 
*   **No Central Server:** Your data never leaves your machine unless you initiate a Cloud Sync.
*   **No Password Reset:** There is no "I forgot my password" button on a server. Your **Recovery Protocol Kit** (Phrase + Salts) is your ONLY lifeline.
*   **Local Sovereignty:** You own your keys. You own your data.

---

*Developed with ❤️ by **[Manoranjan](https://github.com/manoranjan2050)** — Innovating at the intersection of Hardware, Software, and Finance.*
