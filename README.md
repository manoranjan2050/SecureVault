# SecureVault (Elite Edition)

**Version:** 2.0.0-Elite  
**Security Level:** High (Argon2id + AES-256-GCM)  
**Developer:** MANORANJAN  
**GitHub:** <https://github.com/manoranjan2050>  
**Website:** <https://manoranjan.dev>  
**History:** [CHANGELOG.md](CHANGELOG.md)

SecureVault is a premium, portable Flask-based application for secure offline storage. It features a modern, animated Tailwind CSS interface and bit-level encryption for your most sensitive digital assets.

## 🚀 Elite Features

- **Modern Glassmorphism UI:** A sleek, dark-themed, animated interface built with Tailwind CSS and FontAwesome 6.
- **Advanced Password Vault:** Comprehensive storage for Name, Username, Password, Email, Mobile No, URL, and Notes.
- **Intelligent TOTP Authenticator:** Native support for Google Authenticator secrets with automatic padding handling.
- **QR Code Batch Import:** Instantly migrate all 2FA accounts via Google Authenticator migration QR codes or standard setup links.
- **Live Real-time Sync:** Smoothly animated countdown timers and progress rings that refresh cryptographic codes automatically.
- **Real-time Security Audit:** Color-coded entropy meter (from "Critical" to "Elite Protection") and system-wide health diagnostics.
- **Interactive Command Center:** High-density dashboard with recent activity tracking and system-wide statistics.
- **Authenticated Entry:** Industry-standard Argon2id key derivation and AES-256-GCM data sealing.
- **Multi-Site Records Vault:** Specialized templates for Demat, Bank, Trading, Insurance, Mutual Funds, Crypto, and more.
- **Secure Document Cloud:** Encrypted storage for PDFs and images with in-browser secure previewing.
- **Self-Destruct Queue:** Advanced trash management with restorable objects and permanent purge protocols.
- **Security Ledger:** Integrated audit logging to track every system event and authentication attempt.

## 📦 Quick Start

1. Double-click `start.bat` (Initializes environment and starts the vault).
2. Open your secure browser to: `http://127.0.0.1:5000`.
3. Follow the **System Initialization** to create your Master Key.

## 🛠️ Tech Stack

- **Backend:** Python 3.10+, Flask, SQLite 3.
- **Encryption:** `cryptography` (AES-GCM), `argon2-cffi` (ID Type).
- **Frontend:** Tailwind CSS (CDN), Vanilla JS, FontAwesome 6 Pro.
- **Reliability:** Built-in auto-backup system and emergency recovery phrase.

## 🔨 Build Standalone EXE

To generate a portable Windows executable:
1. Run `build_exe.bat`.
2. Find your binary in: `dist\SecureVault\SecureVault.exe`.

## 🛡️ Critical Security Note

SecureVault is a **Zero-Knowledge, Offline Local Vault**. All cryptographic materials, encrypted shards, and backups reside strictly within your local environment. If both the **Master Password** and **Recovery Phrase** are lost, data recovery is mathematically impossible.

---
*Developed by **[Manoranjan](https://github.com/manoranjan2050)** — Innovating at the intersection of Hardware, Software, and Finance.*

