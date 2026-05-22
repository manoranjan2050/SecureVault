# SecureVault Project Files

This project is already separated into individual files. Keep this folder structure:

```text
SecureVault/
├── app.py
├── requirements.txt
├── start.bat
├── build_exe.bat
├── SecureVault.spec
├── README.md
├── PROJECT_FILES.md
├── data/
│   └── .gitkeep
├── encrypted_files/
│   └── .gitkeep
├── backups/
│   └── .gitkeep
├── static/
│   ├── css/
│   │   └── app.css
│   └── js/
│       └── app.js
└── templates/
    ├── base.html
    ├── login.html
    ├── setup.html
    ├── dashboard.html
    ├── totp.html
    ├── totp_form.html
    ├── health.html
    ├── settings.html
    ├── audit_log.html
    ├── trash.html
    ├── password_history.html
    ├── recover.html
    ├── recovery_kit.html
    ├── change_master_password.html
    ├── passwords.html
    ├── password_form.html
    ├── notes.html
    ├── note_form.html
    ├── documents.html
    ├── financial.html
    └── financial_form.html
```

## Run

Double-click `start.bat`, then open:

```text
http://127.0.0.1:5000
```

## Important

After first run, SecureVault creates private files in `data/`, `encrypted_files/`, and `backups/`. Do not share those folders unless you are intentionally moving your own vault.
