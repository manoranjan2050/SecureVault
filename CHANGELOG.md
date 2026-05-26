# Changelog

All notable changes to **SecureVault** will be documented in this file.

## [2.2.0-Elite] - 2026-05-25
### Added
- **Linux Compatibility:** Created `start.sh` for seamless startup on Linux distributions.
- **Multi-Cloud Redundancy:** Triple-site off-site backup system featuring:
    - **Telegram Cloud Export:** One-click encrypted vault delivery to private chats via @SecureVault2050bot.
    - **GitHub Private Sync:** Automated version-controlled backups to private repositories via GitHub API.
    - **Dropbox Direct Sync:** Instant cloud synchronization to dedicated `/SecureVault` folders.
- **Panic Mode Protocol:** Hidden emergency override in the developer signature to instantly decommission all active data to trash and lock the system.
- **Ephemeral Secret Sharing:** Specialized utility for creating encrypted, one-time-use links with fragment-based key security.
- **Document Categorization:** Professional folder-style management for secure files (Finance, ID, Legal, Certificates, etc.).
- **Privacy Shield:** settings-controlled auto-lock protocol triggered by window blur or tab switching.
- **Security Score Analytics:** Real-time Chart.js visualization of vault integrity on the command center dashboard.

### Changed
- **Settings Architecture:** Completely redesigned configuration hub with independent, modular forms for better data persistence.
- **Secure Dashboard:** Upgraded with high-density stats matrix and security score analytics.
- **Document Registry:** Enhanced table view with category signatures and smart file-type icons.

### Fixed
- **API Form Submission:** Resolved issue where GitHub and Dropbox settings weren't saving due to missing form tags.
- **Environment Stability:** Fixed 'start.bat' pathing and virtual environment activation for all Windows configurations.
- **TOTP Robustness:** Improved Base32 decoding to handle unpadded secrets from mobile authenticators.

---

## [2.0.0-Elite] - 2026-05-25
### Added
- **Premium UI Revamp:** Full transition to Tailwind CSS with Glassmorphism aesthetic.
- **QR Code Batch Import:** Support for Google Authenticator Migration QR codes.
- **Enhanced Password Fields:** Added Email ID and Mobile No storage.

---

## [1.0.0] - Pre-Elite Edition
- Initial Flask implementation with AES-256-GCM encryption.
- Basic storage and recovery phrase system.
