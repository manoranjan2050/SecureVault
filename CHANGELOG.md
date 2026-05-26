# Changelog

All notable changes to **SecureVault** will be documented in this file.

## [2.0.0-Elite] - 2026-05-25
### Added
- **Premium UI Revamp:** Full transition to Tailwind CSS with a modern Glassmorphism aesthetic.
- **QR Code Batch Import:** Support for Google Authenticator Migration QR codes and standard TOTP links.
- **Enhanced Password Fields:** Added dedicated storage for Email ID and Mobile No within password entries.
- **Visual Strength Meter:** Real-time entropy check with color-coded security levels (Critical to Elite).
- **Master Startup Script:** Re-engineered `start.bat` with auto-venv recovery and automated browser launching.
- **Security Ledger:** Branded audit log and secure system event tracking.
- **Self-Destruct Queue:** Advanced trash management system with object restoration.
- **Session Hardening:** Automatic inactivity logout after 1 hour to prevent unauthorized access.
- **Developer Branding:** Integrated GitHub profile and website links on setup and login pages.

### Changed
- **TOTP Engine:** Improved secret validation to handle unpadded Base32 strings automatically.
- **Responsive Design:** Optimized every view for high-end mobile and tablet experiences.
- **Flash Messaging:** Modernized notification system with animated slide-in alerts.

### Fixed
- Resolved "Invalid TOTP Secret" errors caused by missing padding in standard authenticator exports.
- Fixed virtual environment activation pathing issues in Windows environments.
- Corrected logic where certain data fields were hidden during tab transitions.

---

## [1.0.0] - Pre-Elite Edition
- Initial Flask implementation with AES-256-GCM encryption.
- Basic Password, Notes, and Document storage.
- Recovery phrase system.
- Audit logging.
