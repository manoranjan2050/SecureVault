# SecureVault

SecureVault is a portable Flask password, notes, and document vault for local/offline use.

Developer: MANORANJAN  
GitHub: <https://github.com/manoranjan2050>

## Quick Start

1. Double-click `start.bat`.
2. Open `http://127.0.0.1:5000`.
3. Create your master password.

## Build Windows EXE

Run:

```bat
build_exe.bat
```

Then start:

```text
dist\SecureVault\SecureVault.exe
```

## Security Notes

- Master password is used to derive an AES-256-GCM key with Argon2id.
- Passwords, notes, and uploaded files are encrypted before storage.
- Recovery phrase can unlock the wrapped vault key if the master password is forgotten.
- Recovery phrase is shown only once. Print it or save it offline.
- The SQLite database and encrypted files stay inside this folder for easy backup or pen drive use.
- Backup exports are saved as encrypted `.svault` files in `backups/`.
- If you lose both the master password and recovery phrase, the vault cannot be recovered.

## Portable Use

Copy the whole `SecureVault` folder to a pen drive, external hard disk, or Dropbox folder. Keep only trusted backups.

## Records Vault

SecureVault now includes encrypted records for:

- Demat accounts
- Bank accounts
- Trading accounts
- Insurance policies
- Mutual fund folio numbers
- Crypto wallet recovery details
- Income tax portal login
- UPI and payment app details
- Loan accounts
- Credit card details
- Nominee and emergency contact information
- Software license keys
- SIM and telecom account details

## Added Advanced Features

- Password hint on login
- Emergency recovery phrase
- Printable recovery kit
- Offline backup recovery key
- Master password change with full re-encryption
- Encrypted backup export
- Encrypted backup restore
- Daily auto backup after login
- Custom backup folder for HDD, pen drive, or Dropbox
- Vault health check
- Password strength meter
- Favorite / important records
- Audit log without storing secrets
- Auto lock timeout settings
- Built-in TOTP authenticator
- CSV password import from browsers and password managers
- Advanced password filters for weak, duplicate, old, and missing 2FA tag
- Records filters by type and important/favorite
- Trash and restore for deleted vault items
- Password history when a password entry is edited
- Failed-login lockout after repeated wrong master password attempts
- Secure PDF/image preview for encrypted documents
- Windows EXE build script with PyInstaller

## Future Ideas

- Duplicate file detection
- LAN sync between your own devices
