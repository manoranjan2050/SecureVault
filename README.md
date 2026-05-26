# SecureVault (Elite Edition)

**Version:** 2.2.0-Elite  
**Security Level:** High (Argon2id + AES-256-GCM)  
**Developer:** MANORANJAN  
**GitHub:** <https://github.com/manoranjan2050>  
**Website:** <https://manoranjan.dev>  
**History:** [CHANGELOG.md](CHANGELOG.md)

SecureVault is a premium, portable Flask-based application for secure offline storage. It features a modern, animated Tailwind CSS interface and bit-level encryption for your most sensitive digital assets.

## 🚀 Elite Features

### ☁️ Triple-Cloud Redundancy
Secure your data off-site with one-click encrypted exports to:
- **Telegram:** Secure delivery to your private chat via bot.
- **GitHub:** Version-controlled storage in private repositories.
- **Dropbox:** Direct synchronization to your personal cloud folders.

### 🔒 Active System Defense
- **Panic Mode Protocol:** A hidden emergency override that instantly moves all active data to trash and locks the vault.
- **Privacy Shield:** Optional auto-lock protocol that triggers immediately when switching browser tabs or minimizing the window.
- **Ephemeral Secret Sharing:** Integrated utility to create encrypted, self-destructing links for sharing data without exposing it to the server.

### 📂 Advanced Data Architecture
- **Categorized Document Cloud:** Professional file management with specialized categories for ID, Finance, and Legal assets.
- **Intelligent TOTP Authenticator:** Native support for Google Authenticator secrets with QR Batch Import and real-time live-sync timers.
- **Security Score Analytics:** Real-time Chart.js visualization of vault integrity on the main command dashboard.
- **Advanced Password Vault:** Comprehensive storage for Name, Username, Password, Email, Mobile No, URL, and Notes.

## 📦 Quick Start

### Windows
1. Double-click `start.bat` (Initializes environment and starts the vault).
2. Open your secure browser to: `http://127.0.0.1:5000`.

### Linux
1. Open a terminal in the project folder.
2. Run: `chmod +x start.sh && ./start.sh`
3. Follow the **System Initialization** to create your Master Key.

## 🛠️ Tech Stack

- **Backend:** Python 3.10+, Flask, SQLite 3.
- **Encryption:** `cryptography` (AES-GCM), `argon2-cffi`.
- **Frontend:** Tailwind CSS, Vanilla JS, Chart.js, FontAwesome 6 Pro.
- **API Integration:** GitHub API, Dropbox API, Telegram Bot API.

## 🛡️ Critical Security Note

SecureVault is a **Zero-Knowledge, Offline Local Vault**. All cryptographic materials, encrypted shards, and backups reside strictly within your local environment. If both the **Master Password** and **Recovery Phrase** are lost, data recovery is mathematically impossible.

---
*Developed by **[Manoranjan](https://github.com/manoranjan2050)** — Innovating at the intersection of Hardware, Software, and Finance.*
