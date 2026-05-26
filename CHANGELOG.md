# Changelog

All notable changes to **SecureVault** will be documented in this file.

## [2.2.0-Elite] - 2026-05-25
### Added
- **Multi-Cloud Redundancy:** Native integration for GitHub Private Repository and Dropbox direct sync backups.
- **Telegram Cloud Sync:** One-click encrypted export to private Telegram chats.
- **Panic Mode Protocol:** Emergency system override to instantly move all active data to trash and lock the vault.
- **Ephemeral Secret Sharing:** Generate one-time, encrypted links to share sensitive data securely.
- **Security Score Analytics:** Integrated Chart.js donut on dashboard showing vault integrity.
- **Document Categorization:** Professional folder-style management for secure files (Finance, ID, Legal, etc.).
- **Privacy Shield (Auto-Lock):** New security setting to automatically lock the vault when switching browser tabs or minimizing the window.

### Changed
- **Settings UI:** Redesigned configuration hub with dedicated panels for Cloud Sync, Recovery, and System Parameters.
- **Dashboard Hub:** Enhanced with real-time security score and high-density stats matrix.
- **Document Vault:** Upgraded registry table with category signatures and smart file-type icons.

### Fixed
- Improved TOTP secret validation to handle unpadded Base32 strings.
- Fixed virtual environment pathing errors in Windows startup script.

---

## [2.0.0-Elite] - 2026-05-25
### Added
- **Premium UI Revamp:** Full transition to Tailwind CSS with Glassmorphism aesthetic.
- **QR Code Batch Import:** Support for Google Authenticator Migration QR codes.
- **Enhanced Password Fields:** Added Email ID and Mobile No storage.
- **Visual Strength Meter:** Real-time entropy check.
- **Developer Branding:** Integrated GitHub identity and website links.

---

## [1.0.0] - Pre-Elite Edition
- Initial Flask implementation with AES-256-GCM encryption.
- Basic storage and recovery phrase system.
