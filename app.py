from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import mimetypes
import os
import secrets
import sqlite3
import struct
import time
from datetime import datetime
from pathlib import Path
from typing import Any
import cv2
import numpy as np
from PIL import Image
from urllib.parse import parse_qs, urlparse, unquote
from zipfile import ZIP_DEFLATED, ZipFile

import requests
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)


BASE_DIR = Path(__file__).resolve().parent
VAULT_POINTER_PATH = BASE_DIR / "vault_pointer.json"

def get_vault_root() -> Path:
    if VAULT_POINTER_PATH.exists():
        try:
            with open(VAULT_POINTER_PATH, 'r') as f:
                config = json.load(f)
                custom_path = config.get("vault_root")
                if custom_path:
                    p = Path(custom_path)
                    if p.is_dir():
                        return p
        except:
            pass
    return BASE_DIR

def get_vault_paths() -> dict[str, Path]:
    root = get_vault_root()
    data_dir = root / "data"
    # Keep session secret in the app root to avoid invalidating sessions when switching vaults
    app_data_dir = BASE_DIR / "data"
    app_data_dir.mkdir(exist_ok=True)
    
    return {
        "root": root,
        "data": data_dir,
        "backups": root / "backups",
        "encrypted_files": root / "encrypted_files",
        "db": data_dir / "vault.db",
        "flask_secret": app_data_dir / "flask.secret"
    }

def get_db_path() -> Path: return get_vault_paths()["db"]
def get_data_dir() -> Path: return get_vault_paths()["data"]
def get_files_dir() -> Path: return get_vault_paths()["encrypted_files"]
def get_backup_dir() -> Path: return get_vault_paths()["backups"]
def get_flask_secret_path() -> Path: return get_vault_paths()["flask_secret"]

BACKUP_MAGIC = b"SVLT"
DEFAULT_SESSION_TIMEOUT_SECONDS = 15 * 60

ACTIVE_KEYS: dict[str, tuple[bytes, float]] = {}

FINANCIAL_ACCOUNT_TYPES = {
    "demat": {
        "label": "Demat Account",
        "fields": [
            ("account_name", "Demat account name", "text"),
            ("broker", "Demat broker", "text"),
            ("account_no", "Demat account number", "text"),
            ("client_id", "Client ID", "text"),
            ("broker_id", "Broker ID", "text"),
            ("username", "Username", "text"),
            ("password", "Password", "password"),
            ("security_question", "Security question / answer", "textarea"),
            ("email", "Email ID", "email"),
            ("mobile", "Mobile number", "text"),
            ("url", "Login URL", "url"),
            ("notes", "Other details", "textarea"),
        ],
    },
    "bank": {
        "label": "Bank Account",
        "fields": [
            ("bank_name", "Bank name", "text"),
            ("account_holder", "Account holder name", "text"),
            ("account_no", "Bank account number", "text"),
            ("netbanking_username", "Netbanking username", "text"),
            ("netbanking_password", "Netbanking password", "password"),
            ("totp", "TOTP / authenticator secret", "password"),
            ("ifsc", "IFSC code", "text"),
            ("debit_card_no", "Debit card number", "text"),
            ("debit_card_expiry", "Debit card expiry", "text"),
            ("debit_card_cvv", "Debit card CVV", "password"),
            ("debit_card_pin", "Debit card PIN", "password"),
            ("mobile", "Registered mobile number", "text"),
            ("email", "Registered email ID", "email"),
            ("address", "Bank address / home branch", "textarea"),
            ("url", "Netbanking URL", "url"),
            ("notes", "Other required details", "textarea"),
        ],
    },
    "trading": {
        "label": "Trading Account",
        "fields": [
            ("broker_name", "Broker name", "text"),
            ("broker_id", "Broker ID", "text"),
            ("client_id", "Client ID", "text"),
            ("username", "Username", "text"),
            ("password", "Password", "password"),
            ("totp", "TOTP / authenticator secret", "password"),
            ("security_question", "Security question / answer", "textarea"),
            ("mobile", "Registered mobile number", "text"),
            ("email", "Registered email ID", "email"),
            ("url", "Trading login URL", "url"),
            ("notes", "Other required details", "textarea"),
        ],
    },
    "insurance": {
        "label": "Insurance Policy",
        "fields": [
            ("policy_name", "Policy name", "text"),
            ("company", "Insurance company", "text"),
            ("policy_no", "Policy number", "text"),
            ("policy_type", "Policy type", "text"),
            ("sum_assured", "Sum assured / coverage", "text"),
            ("premium", "Premium amount", "text"),
            ("due_date", "Premium due date", "text"),
            ("nominee", "Nominee", "text"),
            ("login_username", "Portal username", "text"),
            ("login_password", "Portal password", "password"),
            ("mobile", "Registered mobile number", "text"),
            ("email", "Registered email ID", "email"),
            ("url", "Portal URL", "url"),
            ("agent_details", "Agent / support details", "textarea"),
            ("notes", "Other details", "textarea"),
        ],
    },
    "mutual_fund": {
        "label": "Mutual Fund Folio",
        "fields": [
            ("amc_name", "AMC / fund house", "text"),
            ("folio_no", "Folio number", "text"),
            ("scheme_name", "Scheme name", "text"),
            ("holding_type", "Holding type", "text"),
            ("pan", "PAN linked", "text"),
            ("mobile", "Registered mobile number", "text"),
            ("email", "Registered email ID", "email"),
            ("nominee", "Nominee", "text"),
            ("login_username", "Portal username", "text"),
            ("login_password", "Portal password", "password"),
            ("url", "Portal URL", "url"),
            ("notes", "Other details", "textarea"),
        ],
    },
    "crypto": {
        "label": "Crypto Wallet",
        "fields": [
            ("wallet_name", "Wallet / exchange name", "text"),
            ("wallet_type", "Wallet type", "text"),
            ("public_address", "Public address", "textarea"),
            ("recovery_phrase", "Recovery phrase / seed words", "textarea"),
            ("private_key", "Private key", "textarea"),
            ("password", "Wallet / exchange password", "password"),
            ("totp", "TOTP / authenticator secret", "password"),
            ("backup_location", "Backup location hint", "text"),
            ("email", "Registered email ID", "email"),
            ("mobile", "Registered mobile number", "text"),
            ("url", "Exchange / wallet URL", "url"),
            ("notes", "Other details", "textarea"),
        ],
    },
    "income_tax": {
        "label": "Income Tax Login",
        "fields": [
            ("pan", "PAN", "text"),
            ("aadhaar", "Aadhaar linked", "text"),
            ("username", "Portal username", "text"),
            ("password", "Portal password", "password"),
            ("mobile", "Registered mobile number", "text"),
            ("email", "Registered email ID", "email"),
            ("tan", "TAN, if any", "text"),
            ("gstin", "GSTIN, if any", "text"),
            ("security_question", "Security question / answer", "textarea"),
            ("url", "Portal URL", "url"),
            ("ca_details", "CA / consultant details", "textarea"),
            ("notes", "Other details", "textarea"),
        ],
    },
    "upi": {
        "label": "UPI / Payment App",
        "fields": [
            ("app_name", "App name", "text"),
            ("upi_id", "UPI ID", "text"),
            ("linked_bank", "Linked bank", "text"),
            ("mobile", "Registered mobile number", "text"),
            ("email", "Registered email ID", "email"),
            ("login_pin", "Login PIN", "password"),
            ("upi_pin_hint", "UPI PIN hint", "password"),
            ("device_binding", "Device binding details", "textarea"),
            ("support_details", "Support details", "textarea"),
            ("notes", "Other details", "textarea"),
        ],
    },
    "loan": {
        "label": "Loan Account",
        "fields": [
            ("lender_name", "Bank / lender name", "text"),
            ("loan_type", "Loan type", "text"),
            ("loan_account_no", "Loan account number", "text"),
            ("customer_id", "Customer ID", "text"),
            ("emi_amount", "EMI amount", "text"),
            ("emi_date", "EMI date", "text"),
            ("interest_rate", "Interest rate", "text"),
            ("tenure", "Tenure / maturity", "text"),
            ("login_username", "Portal username", "text"),
            ("login_password", "Portal password", "password"),
            ("mobile", "Registered mobile number", "text"),
            ("email", "Registered email ID", "email"),
            ("url", "Portal URL", "url"),
            ("notes", "Other details", "textarea"),
        ],
    },
    "credit_card": {
        "label": "Credit Card",
        "fields": [
            ("bank_name", "Bank name", "text"),
            ("card_name", "Card name", "text"),
            ("card_no", "Card number", "text"),
            ("card_holder", "Card holder name", "text"),
            ("expiry", "Expiry", "text"),
            ("cvv", "CVV", "password"),
            ("pin", "PIN", "password"),
            ("credit_limit", "Credit limit", "text"),
            ("billing_date", "Billing date", "text"),
            ("payment_due_date", "Payment due date", "text"),
            ("netbanking_username", "Netbanking username", "text"),
            ("netbanking_password", "Netbanking password", "password"),
            ("mobile", "Registered mobile number", "text"),
            ("email", "Registered email ID", "email"),
            ("url", "Card portal URL", "url"),
            ("notes", "Other details", "textarea"),
        ],
    },
    "nominee": {
        "label": "Nominee / Emergency Contact",
        "fields": [
            ("full_name", "Full name", "text"),
            ("relationship", "Relationship", "text"),
            ("mobile", "Mobile number", "text"),
            ("email", "Email ID", "email"),
            ("address", "Address", "textarea"),
            ("id_proof", "ID proof details", "textarea"),
            ("bank_details", "Bank details, if needed", "textarea"),
            ("linked_accounts", "Linked accounts / policies", "textarea"),
            ("notes", "Other details", "textarea"),
        ],
    },
    "software_license": {
        "label": "Software License",
        "fields": [
            ("software_name", "Software name", "text"),
            ("vendor", "Vendor", "text"),
            ("license_key", "License key", "password"),
            ("registered_email", "Registered email ID", "email"),
            ("account_username", "Account username", "text"),
            ("account_password", "Account password", "password"),
            ("purchase_date", "Purchase date", "text"),
            ("renewal_date", "Renewal date", "text"),
            ("invoice_no", "Invoice / order number", "text"),
            ("url", "Account / download URL", "url"),
            ("notes", "Other details", "textarea"),
        ],
    },
    "sim_telecom": {
        "label": "SIM / Telecom Account",
        "fields": [
            ("provider", "Provider", "text"),
            ("mobile_no", "Mobile number", "text"),
            ("account_no", "Account number / customer ID", "text"),
            ("sim_no", "SIM number / ICCID", "text"),
            ("puk_code", "PUK code", "password"),
            ("plan_name", "Plan name", "text"),
            ("billing_cycle", "Billing cycle", "text"),
            ("login_username", "Portal username", "text"),
            ("login_password", "Portal password", "password"),
            ("registered_email", "Registered email ID", "email"),
            ("address", "Registered address", "textarea"),
            ("url", "Portal URL", "url"),
            ("notes", "Other details", "textarea"),
        ],
    },
}

FINANCIAL_TITLE_FIELDS = {
    "demat": ("account_name", "broker", "username"),
    "bank": ("bank_name", "account_holder", "netbanking_username"),
    "trading": ("broker_name", "username", "client_id"),
    "insurance": ("policy_name", "company", "policy_no"),
    "mutual_fund": ("scheme_name", "amc_name", "folio_no"),
    "crypto": ("wallet_name", "wallet_type", "public_address"),
    "income_tax": ("pan", "username", "email"),
    "upi": ("app_name", "upi_id", "linked_bank"),
    "loan": ("lender_name", "loan_type", "loan_account_no"),
    "credit_card": ("card_name", "bank_name", "card_no"),
    "nominee": ("full_name", "relationship", "mobile"),
    "software_license": ("software_name", "vendor", "registered_email"),
    "sim_telecom": ("mobile_no", "provider", "account_no"),
}

FINANCIAL_SUBTITLE_FIELDS = {
    "demat": ("client_id", "account_no", "username"),
    "bank": ("account_no", "ifsc", "netbanking_username"),
    "trading": ("client_id", "broker_id", "username"),
    "insurance": ("policy_no", "policy_type", "due_date"),
    "mutual_fund": ("folio_no", "amc_name", "pan"),
    "crypto": ("wallet_type", "email", "public_address"),
    "income_tax": ("username", "email", "mobile"),
    "upi": ("upi_id", "mobile", "linked_bank"),
    "loan": ("loan_account_no", "emi_amount", "emi_date"),
    "credit_card": ("card_no", "credit_limit", "payment_due_date"),
    "nominee": ("relationship", "mobile", "email"),
    "software_license": ("license_key", "renewal_date", "invoice_no"),
    "sim_telecom": ("provider", "account_no", "plan_name"),
}


def create_app() -> Flask:
    paths = get_vault_paths()
    paths["data"].mkdir(parents=True, exist_ok=True)
    paths["backups"].mkdir(parents=True, exist_ok=True)
    paths["encrypted_files"].mkdir(parents=True, exist_ok=True)

    app = Flask(__name__)
    app.config["SECRET_KEY"] = load_or_create_flask_secret()
    app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

    init_db()

    @app.template_filter("strftime")
    def _jinja2_filter_datetime(timestamp, format="%Y-%m-%d %H:%M:%S"):
        return datetime.fromtimestamp(timestamp).strftime(format)

    @app.before_request
    def enforce_session_timeout() -> None:
        if request.endpoint in {"static", "login", "setup", "recover"}:
            return
        if is_configured() and request.endpoint != "logout":
            key = get_active_key()
            if key is None:
                session.clear()
                flash("Vault locked. Please log in again.", "info")
                return redirect(url_for("login"))

    @app.context_processor
    def inject_globals() -> dict[str, Any]:
        return {
            "configured": is_configured(),
            "current_year": datetime.now().year,
            "lock_on_blur": get_config_text("lock_on_blur", "0") == "1",
        }

    @app.route("/", methods=["GET", "POST"])
    def login():
        if not is_configured():
            return redirect(url_for("setup"))

        password_hint = get_config_text("password_hint", "")
        requires_keyfile = get_config_text("requires_keyfile", "0") == "1"
        
        if request.method == "POST":
            locked_until = get_login_locked_until()
            if locked_until > time.time():
                wait_seconds = int(locked_until - time.time())
                flash(f"Too many failed attempts. Try again in {wait_seconds} seconds.", "error")
                return render_template("login.html", password_hint=password_hint, requires_keyfile=requires_keyfile)

            password = request.form.get("master_password", "")
            keyfile = request.files.get("keyfile")
            keyfile_data = keyfile.read() if keyfile else b""
            
            try:
                key = derive_key(password, get_config_value("kdf_salt"), keyfile_data)
                decrypt_text(get_config_value("vault_check"), key)
            except (InvalidTag, ValueError):
                register_failed_login()
                log_audit("failed_login", "Master password login failed")
                flash("Master password or keyfile is incorrect.", "error")
                return render_template("login.html", password_hint=password_hint, requires_keyfile=requires_keyfile)

            reset_failed_logins()
            token = secrets.token_urlsafe(32)
            ACTIVE_KEYS[token] = (key, time.time())
            session.clear()
            session["vault_token"] = token
            log_audit("login", "Vault unlocked")
            run_auto_backup(key)
            flash("Vault unlocked.", "success")
            return redirect(url_for("dashboard"))

        return render_template("login.html", password_hint=password_hint, requires_keyfile=requires_keyfile, vault_root=str(get_vault_root()))

    @app.route("/switch-vault", methods=["POST"])
    def switch_vault():
        new_path = request.form.get("vault_root", "").strip()
        if not new_path:
            if VAULT_POINTER_PATH.exists():
                VAULT_POINTER_PATH.unlink()
            flash("Vault switched to default location.", "info")
            return redirect(url_for("login"))
            
        p = Path(new_path)
        if not p.is_dir():
            flash("Invalid vault directory path.", "error")
            return redirect(url_for("login"))
            
        with open(VAULT_POINTER_PATH, 'w') as f:
            json.dump({"vault_root": str(p.absolute())}, f)
            
        flash(f"Vault switched to: {p.name}", "success")
        return redirect(url_for("login"))

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if is_configured():
            return redirect(url_for("login"))

        if request.method == "POST":
            # 1. Handle Vault Location if provided
            vault_root = request.form.get("vault_root", "").strip()
            if vault_root:
                p = Path(vault_root)
                if not p.is_dir():
                    try:
                        p.mkdir(parents=True, exist_ok=True)
                    except Exception as e:
                        flash(f"Could not create vault directory: {str(e)}", "error")
                        return render_template("setup.html")
                
                with open(VAULT_POINTER_PATH, 'w') as f:
                    json.dump({"vault_root": str(p.absolute())}, f)
                
                # Re-initialize directories in the new location
                paths = get_vault_paths()
                paths["data"].mkdir(parents=True, exist_ok=True)
                paths["backups"].mkdir(parents=True, exist_ok=True)
                paths["encrypted_files"].mkdir(parents=True, exist_ok=True)

            # 2. Extract Keyfile Data
            keyfile = request.files.get("keyfile")
            keyfile_data = keyfile.read() if keyfile else b""

            # 3. Handle Restoration
            if "restore_vault" in request.form:
                password = request.form.get("master_password", "")
                uploaded = request.files.get("backup_file")
                if not uploaded or not uploaded.filename:
                    flash("Select a .svault backup file first.", "error")
                    return render_template("setup.html")
                
                try:
                    data = uploaded.read()
                    salt = None
                    
                    if data.startswith(BACKUP_MAGIC):
                        salt = data[4:20]
                    else:
                        legacy_salt_hex = request.form.get("legacy_salt", "").strip()
                        if not legacy_salt_hex:
                            flash("This is a legacy backup. Please provide the 16-byte HEX salt.", "error")
                            return render_template("setup.html")
                        try:
                            salt = bytes.fromhex(legacy_salt_hex)
                            if len(salt) != 16: raise ValueError()
                        except ValueError:
                            flash("Invalid legacy salt.", "error")
                            return render_template("setup.html")
                    
                    key = derive_key(password, salt, keyfile_data)
                    restore_backup_bytes(data, key)
                    set_config_value("kdf_salt", salt)
                    set_config_value("requires_keyfile", "1" if keyfile_data else "0")
                    
                    token = secrets.token_urlsafe(32)
                    ACTIVE_KEYS[token] = (key, time.time())
                    session.clear()
                    session["vault_token"] = token
                    log_audit("setup_restore", "Vault restored during setup")
                    flash("Vault successfully restored.", "success")
                    return redirect(url_for("dashboard"))
                except Exception as e:
                    flash(f"Restoration failed: {str(e)}", "error")
                    return render_template("setup.html")

            # 4. Create New Vault
            password = request.form.get("master_password", "")
            confirm = request.form.get("confirm_password", "")
            password_hint = request.form.get("password_hint", "").strip()
            if len(password) < 10:
                flash("Use at least 10 characters for the master password.", "error")
                return render_template("setup.html")
            if password != confirm:
                flash("Master passwords do not match.", "error")
                return render_template("setup.html")

            salt = os.urandom(16)
            key = derive_key(password, salt, keyfile_data)
            recovery_phrase = generate_recovery_phrase()
            recovery_salt = os.urandom(16)
            recovery_key = derive_key(recovery_phrase, recovery_salt)
            
            init_db() # Ensure DB is initialized at the new location
            set_config_value("kdf_salt", salt)
            set_config_value("vault_check", encrypt_text("securevault-ok", key))
            set_config_value("password_hint", password_hint)
            set_config_value("requires_keyfile", "1" if keyfile_data else "0")
            set_config_value("recovery_salt", recovery_salt)
            set_config_value("recovery_check", encrypt_text("securevault-recovery-ok", recovery_key))
            set_config_value("recovery_wrapped_key", wrap_key(key, recovery_key))
            set_config_value("session_timeout_seconds", str(DEFAULT_SESSION_TIMEOUT_SECONDS))
            set_config_value("auto_backup_enabled", "1")
            set_config_value("created_at", now_iso())

            token = secrets.token_urlsafe(32)
            ACTIVE_KEYS[token] = (key, time.time())
            session.clear()
            session["vault_token"] = token
            session["recovery_phrase_once"] = recovery_phrase
            log_audit("setup", "Vault created")
            flash("SecureVault is ready.", "success")
            return redirect(url_for("recovery_kit"))

        return render_template("setup.html", base_dir=str(BASE_DIR))

    @app.route("/recover", methods=["GET", "POST"])
    def recover():
        if not is_configured():
            return redirect(url_for("setup"))

        if request.method == "POST":
            recovery_phrase = request.form.get("recovery_phrase", "").strip()
            new_password = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            
            keyfile = request.files.get("keyfile")
            keyfile_data = keyfile.read() if keyfile else b""
            
            if len(new_password) < 10:
                flash("Use at least 10 characters for the new master password.", "error")
                return render_template("recover.html")
            if new_password != confirm:
                flash("New passwords do not match.", "error")
                return render_template("recover.html")

            try:
                # Recovery phrase derivation never uses a keyfile for safety
                recovery_key = derive_key(recovery_phrase, get_config_value("recovery_salt"))
                decrypt_text(get_config_value("recovery_check"), recovery_key)
                old_key = unwrap_key(get_config_value("recovery_wrapped_key"), recovery_key)
            except (InvalidTag, ValueError):
                log_audit("failed_recovery", "Recovery phrase failed")
                flash("Recovery phrase is incorrect.", "error")
                return render_template("recover.html")

            new_salt = os.urandom(16)
            new_key = derive_key(new_password, new_salt, keyfile_data)
            new_recovery_phrase = generate_recovery_phrase()
            new_recovery_salt = os.urandom(16)
            new_recovery_key = derive_key(new_recovery_phrase, new_recovery_salt)
            
            reencrypt_vault(old_key, new_key)
            set_config_value("kdf_salt", new_salt)
            set_config_value("vault_check", encrypt_text("securevault-ok", new_key))
            set_config_value("requires_keyfile", "1" if keyfile_data else "0")
            set_config_value("recovery_salt", new_recovery_salt)
            set_config_value("recovery_check", encrypt_text("securevault-recovery-ok", new_recovery_key))
            set_config_value("recovery_wrapped_key", wrap_key(new_key, new_recovery_key))

            token = secrets.token_urlsafe(32)
            ACTIVE_KEYS[token] = (new_key, time.time())
            session.clear()
            session["vault_token"] = token
            session["recovery_phrase_once"] = new_recovery_phrase
            log_audit("recovery", "Vault recovered with recovery phrase")
            flash("Vault recovered. Print or save the new recovery kit.", "success")
            return redirect(url_for("recovery_kit"))

        return render_template("recover.html")

    @app.route("/dashboard")
    def dashboard():
        key = require_key()
        health = vault_health_report(key)
        requires_keyfile = get_config_text("requires_keyfile", "0") == "1"
        stats = {
            "passwords": health["total_passwords"],
            "notes": query_scalar("SELECT COUNT(*) FROM secure_notes"),
            "documents": health["documents"],
            "financial": health["records"],
            "totp": query_scalar("SELECT COUNT(*) FROM totp_accounts"),
            "backups": len(list(get_backup_dir().glob("*.svault"))),
            "health": health,
            "requires_keyfile": requires_keyfile
        }
        recent_passwords = fetch_all(
            "SELECT id, title, username, tags, updated_at FROM passwords ORDER BY updated_at DESC LIMIT 5"
        )
        recent_notes = fetch_all(
            "SELECT id, title, category, updated_at FROM secure_notes ORDER BY updated_at DESC LIMIT 5"
        )
        return render_template(
            "dashboard.html",
            stats=stats,
            recent_passwords=recent_passwords,
            recent_notes=recent_notes,
        )

    @app.route("/panic", methods=["POST"])
    def panic_mode():
        key = require_key()
        # Move all items to trash
        for row in fetch_all("SELECT * FROM passwords"):
            move_to_trash(key, "password", row["title"], dict(row))
        for row in fetch_all("SELECT * FROM secure_notes"):
            move_to_trash(key, "secure_note", row["title"], dict(row))
        for row in fetch_all("SELECT * FROM financial_accounts"):
            data = decrypt_json(row["encrypted_data"], key)
            move_to_trash(key, "financial_account", financial_title(row["account_type"], data), dict(row))
        
        execute("DELETE FROM passwords")
        execute("DELETE FROM secure_notes")
        execute("DELETE FROM financial_accounts")
        
        log_audit("panic_mode", "PANIC MODE TRIGGERED: All active entries moved to trash and vault locked.")
        return redirect(url_for("lock"))

    @app.route("/share", methods=["GET", "POST"])
    def share_message():
        key = require_key()
        if request.method == "POST":
            content = request.form.get("content", "").strip()
            if not content:
                flash("Message cannot be empty.", "error")
                return redirect(url_for("share_message"))
            
            msg_id = secrets.token_urlsafe(16)
            # Share key is independent of master key for safety
            share_key = secrets.token_urlsafe(32).encode('ascii')[:32]
            encrypted = encrypt_text(content, share_key)
            
            execute(
                "INSERT INTO shared_messages (id, encrypted_content, expires_at) VALUES (?, ?, ?)",
                (msg_id, encrypted, (time.time() + 3600)) # 1 hour expiry
            )
            
            full_link = f"{request.host_url}view-shared/{msg_id}#{share_key.decode('ascii')}"
            return render_template("share_result.html", link=full_link)
            
        return render_template("share_form.html")

    @app.route("/view-shared/<msg_id>")
    def view_shared(msg_id: str):
        row = fetch_one("SELECT * FROM shared_messages WHERE id = ?", (msg_id,))
        if not row:
            return render_template("share_expired.html"), 404
            
        return render_template("share_view.html", msg_id=msg_id)

    @app.route("/api/decrypt-shared/<msg_id>", methods=["POST"])
    def decrypt_shared(msg_id: str):
        row = fetch_one("SELECT * FROM shared_messages WHERE id = ?", (msg_id,))
        if not row:
            return json.dumps({"error": "Expired"}), 404
            
        share_key = request.json.get("key", "").encode('ascii')
        try:
            decrypted = decrypt_text(row["encrypted_content"], share_key)
            execute("DELETE FROM shared_messages WHERE id = ?", (msg_id,))
            return json.dumps({"content": decrypted})
        except:
            return json.dumps({"error": "Invalid Key"}), 403

    @app.route("/financial")
    def financial_accounts():
        key = require_key()
        search = request.args.get("q", "").strip()
        selected_type = request.args.get("type", "").strip()
        favorites_only = request.args.get("favorite") == "1"
        rows = fetch_all("SELECT * FROM financial_accounts ORDER BY updated_at DESC")
        entries = []
        for row in rows:
            data = decrypt_json(row["encrypted_data"], key)
            account_type = row["account_type"]
            if selected_type and account_type != selected_type:
                continue
            if favorites_only and not row["favorite"]:
                continue
            type_config = FINANCIAL_ACCOUNT_TYPES.get(account_type, FINANCIAL_ACCOUNT_TYPES["bank"])
            entry = {
                "id": row["id"],
                "account_type": account_type,
                "type_label": type_config["label"],
                "title": financial_title(account_type, data),
                "subtitle": financial_subtitle(account_type, data),
                "favorite": bool(row["favorite"]),
                "data": data,
                "updated_at": row["updated_at"],
            }
            haystack = " ".join([entry["type_label"], entry["title"], entry["subtitle"], *data.values()])
            if search and search.lower() not in haystack.lower():
                continue
            entries.append(entry)
        return render_template(
            "financial.html",
            entries=entries,
            search=search,
            account_types=FINANCIAL_ACCOUNT_TYPES,
            selected_type=selected_type,
            favorites_only=favorites_only,
        )

    @app.route("/financial/add/<account_type>", methods=["GET", "POST"])
    def add_financial_account(account_type: str):
        key = require_key()
        type_config = FINANCIAL_ACCOUNT_TYPES.get(account_type)
        if type_config is None:
            flash("Financial account type not found.", "error")
            return redirect(url_for("financial_accounts"))

        if request.method == "POST":
            data = financial_form_data(type_config)
            now = now_iso()
            execute(
                """
                INSERT INTO financial_accounts
                    (account_type, encrypted_data, favorite, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (account_type, encrypt_json(data, key), form_checkbox("favorite"), now, now),
            )
            flash(f"{type_config['label']} saved securely.", "success")
            return redirect(url_for("financial_accounts"))

        return render_template(
            "financial_form.html",
            entry=None,
            account_type=account_type,
            type_config=type_config,
        )

    @app.route("/financial/<int:entry_id>/edit", methods=["GET", "POST"])
    def edit_financial_account(entry_id: int):
        key = require_key()
        row = fetch_one("SELECT * FROM financial_accounts WHERE id = ?", (entry_id,))
        if row is None:
            flash("Financial account not found.", "error")
            return redirect(url_for("financial_accounts"))

        account_type = row["account_type"]
        type_config = FINANCIAL_ACCOUNT_TYPES.get(account_type, FINANCIAL_ACCOUNT_TYPES["bank"])
        entry = {
            "id": row["id"],
            "favorite": bool(row["favorite"]),
            "data": decrypt_json(row["encrypted_data"], key),
        }

        if request.method == "POST":
            execute(
                """
                UPDATE financial_accounts
                SET encrypted_data = ?, favorite = ?, updated_at = ?
                WHERE id = ?
                """,
                (encrypt_json(financial_form_data(type_config), key), form_checkbox("favorite"), now_iso(), entry_id),
            )
            flash(f"{type_config['label']} updated.", "success")
            return redirect(url_for("financial_accounts"))

        return render_template(
            "financial_form.html",
            entry=entry,
            account_type=account_type,
            type_config=type_config,
        )

    @app.route("/financial/<int:entry_id>/delete", methods=["POST"])
    def delete_financial_account(entry_id: int):
        key = require_key()
        row = fetch_one("SELECT * FROM financial_accounts WHERE id = ?", (entry_id,))
        if row:
            move_to_trash(
                key,
                "financial_account",
                financial_title(row["account_type"], decrypt_json(row["encrypted_data"], key)),
                dict(row),
            )
            execute("DELETE FROM financial_accounts WHERE id = ?", (entry_id,))
        flash("Financial account moved to trash.", "success")
        return redirect(url_for("financial_accounts"))

    @app.route("/passwords")
    def passwords():
        key = require_key()
        search = request.args.get("q", "").strip()
        selected_filter = request.args.get("filter", "").strip()
        rows = fetch_all("SELECT * FROM passwords ORDER BY updated_at DESC")
        all_passwords = []
        for row in rows:
            all_passwords.append(decrypt_text(row["encrypted_password"], key))
        duplicate_values = {password for password in all_passwords if all_passwords.count(password) > 1}
        entries = []
        for row in rows:
            decrypted = dict(row)
            decrypted["password"] = decrypt_text(row["encrypted_password"], key)
            decrypted["notes"] = decrypt_text(row["encrypted_notes"], key)
            decrypted["strength_score"] = password_score(decrypted["password"])
            decrypted["is_weak"] = decrypted["strength_score"] < 3
            decrypted["is_duplicate"] = decrypted["password"] in duplicate_values
            decrypted["is_old"] = is_old_date(row["updated_at"])
            decrypted["missing_2fa"] = "2fa" not in (row["tags"] or "").lower() and "totp" not in (row["tags"] or "").lower()
            if search and search.lower() not in " ".join(
                [
                    decrypted["title"],
                    decrypted["website"] or "",
                    decrypted["username"] or "",
                    decrypted["tags"] or "",
                    decrypted["notes"] or "",
                ]
            ).lower():
                continue
            if selected_filter == "weak" and not decrypted["is_weak"]:
                continue
            if selected_filter == "duplicate" and not decrypted["is_duplicate"]:
                continue
            if selected_filter == "old" and not decrypted["is_old"]:
                continue
            if selected_filter == "missing_2fa" and not decrypted["missing_2fa"]:
                continue
            entries.append(decrypted)
        return render_template("passwords.html", entries=entries, search=search, selected_filter=selected_filter)

    @app.route("/passwords/import", methods=["POST"])
    def import_passwords():
        key = require_key()
        uploaded = request.files.get("csv_file")
        if not uploaded or not uploaded.filename:
            flash("Choose a CSV file first.", "error")
            return redirect(url_for("passwords"))
        try:
            imported = import_password_csv(uploaded.read(), key)
        except (UnicodeDecodeError, csv.Error, ValueError):
            flash("CSV import failed. Check the file format.", "error")
            return redirect(url_for("passwords"))
        log_audit("csv_import", f"Imported {imported} password rows")
        flash(f"Imported {imported} passwords.", "success")
        return redirect(url_for("passwords"))

    @app.route("/passwords/add", methods=["GET", "POST"])
    def add_password():
        key = require_key()
        if request.method == "POST":
            now = now_iso()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            if password != confirm:
                flash("Passwords do not match.", "error")
                return render_template("password_form.html", entry=None)
                
            execute(
                """
                INSERT INTO passwords
                    (title, website, username, email_id, mobile_no, encrypted_password, encrypted_notes, tags, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.form.get("title", "").strip(),
                    request.form.get("website", "").strip(),
                    request.form.get("username", "").strip(),
                    request.form.get("email_id", "").strip(),
                    request.form.get("mobile_no", "").strip(),
                    encrypt_text(password, key),
                    encrypt_text(request.form.get("notes", ""), key),
                    request.form.get("tags", "").strip(),
                    now,
                    now,
                ),
            )
            flash("Password saved securely.", "success")
            return redirect(url_for("passwords"))
        return render_template("password_form.html", entry=None)

    @app.route("/passwords/<int:entry_id>/edit", methods=["GET", "POST"])
    def edit_password(entry_id: int):
        key = require_key()
        row = fetch_one("SELECT * FROM passwords WHERE id = ?", (entry_id,))
        if row is None:
            flash("Password entry not found.", "error")
            return redirect(url_for("passwords"))

        entry = dict(row)
        entry["password"] = decrypt_text(row["encrypted_password"], key)
        entry["notes"] = decrypt_text(row["encrypted_notes"], key)

        if request.method == "POST":
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            if password != confirm:
                flash("Passwords do not match.", "error")
                return render_template("password_form.html", entry=entry)
                
            save_password_history(key, row)
            execute(
                """
                UPDATE passwords
                SET title = ?, website = ?, username = ?, email_id = ?, mobile_no = ?,
                    encrypted_password = ?, encrypted_notes = ?, tags = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    request.form.get("title", "").strip(),
                    request.form.get("website", "").strip(),
                    request.form.get("username", "").strip(),
                    request.form.get("email_id", "").strip(),
                    request.form.get("mobile_no", "").strip(),
                    encrypt_text(password, key),
                    encrypt_text(request.form.get("notes", ""), key),
                    request.form.get("tags", "").strip(),
                    now_iso(),
                    entry_id,
                ),
            )
            flash("Password updated.", "success")
            return redirect(url_for("passwords"))

        return render_template("password_form.html", entry=entry)

    @app.route("/passwords/<int:entry_id>/delete", methods=["POST"])
    def delete_password(entry_id: int):
        key = require_key()
        row = fetch_one("SELECT * FROM passwords WHERE id = ?", (entry_id,))
        if row:
            move_to_trash(key, "password", row["title"], dict(row))
            execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
        flash("Password moved to trash.", "success")
        return redirect(url_for("passwords"))

    @app.route("/totp")
    def totp_accounts():
        key = require_key()
        search = request.args.get("q", "").strip()
        rows = fetch_all("SELECT * FROM totp_accounts ORDER BY issuer, account_name")
        entries = []
        now = int(time.time())
        for row in rows:
            secret = decrypt_text(row["encrypted_secret"], key)
            entry = dict(row)
            entry["secret"] = secret
            entry["code"] = generate_totp(secret, row["digits"], row["period"], row["algorithm"])
            entry["seconds_left"] = row["period"] - (now % row["period"])
            if search and search.lower() not in " ".join([row["issuer"], row["account_name"], row["notes"] or ""]).lower():
                continue
            entries.append(entry)
        return render_template("totp.html", entries=entries, search=search)

    @app.route("/totp/add", methods=["GET", "POST"])
    def add_totp():
        key = require_key()
        if request.method == "POST":
            secret = normalize_totp_secret(request.form.get("secret", ""))
            if not is_valid_totp_secret(secret):
                flash("TOTP secret is invalid. Use the Base32 secret from your authenticator setup.", "error")
                return render_template("totp_form.html", entry=None)
            now = now_iso()
            execute(
                """
                INSERT INTO totp_accounts
                    (issuer, account_name, encrypted_secret, digits, period, algorithm, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.form.get("issuer", "").strip(),
                    request.form.get("account_name", "").strip(),
                    encrypt_text(secret, key),
                    int(request.form.get("digits", "6")),
                    int(request.form.get("period", "30")),
                    request.form.get("algorithm", "SHA1"),
                    request.form.get("notes", "").strip(),
                    now,
                    now,
                ),
            )
            log_audit("totp_add", "TOTP account added")
            flash("TOTP account saved.", "success")
            return redirect(url_for("totp_accounts"))
        return render_template("totp_form.html", entry=None)

    @app.route("/totp/<int:entry_id>/edit", methods=["GET", "POST"])
    def edit_totp(entry_id: int):
        key = require_key()
        row = fetch_one("SELECT * FROM totp_accounts WHERE id = ?", (entry_id,))
        if row is None:
            flash("TOTP account not found.", "error")
            return redirect(url_for("totp_accounts"))
        entry = dict(row)
        entry["secret"] = decrypt_text(row["encrypted_secret"], key)
        if request.method == "POST":
            secret = normalize_totp_secret(request.form.get("secret", ""))
            if not is_valid_totp_secret(secret):
                flash("TOTP secret is invalid.", "error")
                return render_template("totp_form.html", entry=entry)
            execute(
                """
                UPDATE totp_accounts
                SET issuer = ?, account_name = ?, encrypted_secret = ?, digits = ?,
                    period = ?, algorithm = ?, notes = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    request.form.get("issuer", "").strip(),
                    request.form.get("account_name", "").strip(),
                    encrypt_text(secret, key),
                    int(request.form.get("digits", "6")),
                    int(request.form.get("period", "30")),
                    request.form.get("algorithm", "SHA1"),
                    request.form.get("notes", "").strip(),
                    now_iso(),
                    entry_id,
                ),
            )
            log_audit("totp_update", "TOTP account updated")
            flash("TOTP account updated.", "success")
            return redirect(url_for("totp_accounts"))
        return render_template("totp_form.html", entry=entry)

    @app.route("/totp/<int:entry_id>/delete", methods=["POST"])
    def delete_totp(entry_id: int):
        key = require_key()
        row = fetch_one("SELECT * FROM totp_accounts WHERE id = ?", (entry_id,))
        if row:
            move_to_trash(key, "totp", row["issuer"] or row["account_name"], dict(row))
            execute("DELETE FROM totp_accounts WHERE id = ?", (entry_id,))
        log_audit("totp_delete", "TOTP account deleted")
        flash("TOTP account moved to trash.", "success")
        return redirect(url_for("totp_accounts"))

    @app.route("/notes")
    def notes():
        key = require_key()
        search = request.args.get("q", "").strip()
        rows = fetch_all("SELECT * FROM secure_notes ORDER BY updated_at DESC")
        entries = []
        for row in rows:
            decrypted = dict(row)
            try:
                decrypted["content"] = decrypt_text(row["encrypted_content"], key)
            except Exception:
                decrypted["content"] = "[DECRYPTION ERROR: Possible key mismatch or corrupted data]"
                
            if search and search.lower() not in " ".join(
                [decrypted["title"], decrypted["category"] or "", decrypted["content"]]
            ).lower():
                continue
            entries.append(decrypted)
        return render_template("notes.html", entries=entries, search=search)

    @app.route("/notes/add", methods=["GET", "POST"])
    def add_note():
        key = require_key()
        if request.method == "POST":
            now = now_iso()
            execute(
                """
                INSERT INTO secure_notes
                    (title, encrypted_content, category, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    request.form.get("title", "").strip(),
                    encrypt_text(request.form.get("content", ""), key),
                    request.form.get("category", "").strip(),
                    now,
                    now,
                ),
            )
            flash("Secure note saved.", "success")
            return redirect(url_for("notes"))
        return render_template("note_form.html", entry=None)

    @app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
    def edit_note(note_id: int):
        key = require_key()
        row = fetch_one("SELECT * FROM secure_notes WHERE id = ?", (note_id,))
        if row is None:
            flash("Secure note not found.", "error")
            return redirect(url_for("notes"))

        entry = dict(row)
        entry["content"] = decrypt_text(row["encrypted_content"], key)
        if request.method == "POST":
            execute(
                """
                UPDATE secure_notes
                SET title = ?, encrypted_content = ?, category = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    request.form.get("title", "").strip(),
                    encrypt_text(request.form.get("content", ""), key),
                    request.form.get("category", "").strip(),
                    now_iso(),
                    note_id,
                ),
            )
            flash("Secure note updated.", "success")
            return redirect(url_for("notes"))
        return render_template("note_form.html", entry=entry)

    @app.route("/notes/<int:note_id>/delete", methods=["POST"])
    def delete_note(note_id: int):
        key = require_key()
        row = fetch_one("SELECT * FROM secure_notes WHERE id = ?", (note_id,))
        if row:
            move_to_trash(key, "secure_note", row["title"], dict(row))
            execute("DELETE FROM secure_notes WHERE id = ?", (note_id,))
        flash("Secure note moved to trash.", "success")
        return redirect(url_for("notes"))

    @app.route("/documents", methods=["GET", "POST"])
    def documents():
        key = require_key()
        if request.method == "POST":
            uploaded = request.files.get("document")
            if not uploaded or not uploaded.filename:
                flash("Choose a file first.", "error")
                return redirect(url_for("documents"))

            category = request.form.get("category", "Uncategorized").strip()
            original_name = Path(uploaded.filename).name
            data = uploaded.read()
            mime_type = uploaded.mimetype or guess_mime_type(original_name)
            encrypted_blob = encrypt_bytes(data, key)
            stored_name = f"{secrets.token_hex(16)}.bin"
            stored_path = get_files_dir() / stored_name
            stored_path.write_bytes(encrypted_blob)
            now = now_iso()
            execute(
                """
                INSERT INTO documents
                    (filename, stored_name, file_size, mime_type, category, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (original_name, stored_name, len(data), mime_type, category, now),
            )
            flash("Document encrypted and saved.", "success")
            return redirect(url_for("documents"))

        rows = fetch_all("SELECT * FROM documents ORDER BY category ASC, created_at DESC")
        return render_template("documents.html", entries=rows)

    @app.route("/documents/<int:doc_id>/download")
    def download_document(doc_id: int):
        key = require_key()
        row = fetch_one("SELECT * FROM documents WHERE id = ?", (doc_id,))
        if row is None:
            flash("Document not found.", "error")
            return redirect(url_for("documents"))

        encrypted_path = get_files_dir() / row["stored_name"]
        if not encrypted_path.exists():
            flash("Encrypted file is missing.", "error")
            return redirect(url_for("documents"))

        decrypted = io.BytesIO(decrypt_bytes(encrypted_path.read_bytes(), key))
        log_audit("document_download", f"Downloaded document: {row['filename']}")
        return send_file(decrypted, as_attachment=True, download_name=row["filename"])

    @app.route("/documents/<int:doc_id>/preview")
    def preview_document(doc_id: int):
        key = require_key()
        row = fetch_one("SELECT * FROM documents WHERE id = ?", (doc_id,))
        if row is None:
            flash("Document not found.", "error")
            return redirect(url_for("documents"))

        mime_type = row["mime_type"] or guess_mime_type(row["filename"])
        if not is_previewable_mime(mime_type):
            flash("Preview is available only for PDF and image files.", "error")
            return redirect(url_for("documents"))

        encrypted_path = get_files_dir() / row["stored_name"]
        if not encrypted_path.exists():
            flash("Encrypted file is missing.", "error")
            return redirect(url_for("documents"))

        decrypted = io.BytesIO(decrypt_bytes(encrypted_path.read_bytes(), key))
        log_audit("document_preview", f"Previewed document: {row['filename']}")
        return send_file(decrypted, mimetype=mime_type, as_attachment=False, download_name=row["filename"])

    @app.route("/documents/<int:doc_id>/delete", methods=["POST"])
    def delete_document(doc_id: int):
        key = require_key()
        row = fetch_one("SELECT * FROM documents WHERE id = ?", (doc_id,))
        if row:
            move_to_trash(key, "document", row["filename"], dict(row))
            execute("DELETE FROM documents WHERE id = ?", (doc_id,))
            flash("Document moved to trash.", "success")
        return redirect(url_for("documents"))

    @app.route("/maintenance", methods=["GET", "POST"])
    def maintenance():
        require_key()
        if request.method == "POST":
            if "create_local_backup" in request.form:
                try:
                    key = require_key()
                    path = create_backup_file(key)
                    flash(f"Local backup created: {path.name}", "success")
                except Exception as e:
                    flash(f"Backup failed: {str(e)}", "error")
                return redirect(url_for("maintenance"))

        backups = sorted(get_backup_dir().glob("*.svault"), key=lambda x: x.stat().st_mtime, reverse=True)
        return render_template(
            "maintenance.html",
            backups=backups,
            telegram_bot_token=get_config_text("telegram_bot_token", ""),
            telegram_chat_id=get_config_text("telegram_chat_id", ""),
            github_token=get_config_text("github_token", ""),
            github_repo=get_config_text("github_repo", ""),
            dropbox_token=get_config_text("dropbox_token", ""),
        )

    @app.route("/backup/local")
    def backup_download():
        key = require_key()
        try:
            path = create_backup_file(key)
            return send_file(path, as_attachment=True, download_name=path.name)
        except Exception as e:
            flash(f"Local backup failed: {str(e)}", "error")
            return redirect(url_for("maintenance"))

    @app.route("/backup/telegram")
    def telegram_backup():
        key = require_key()
        bot_token = get_config_text("telegram_bot_token", "").strip()
        chat_id = get_config_text("telegram_chat_id", "").strip()
        if not bot_token or not chat_id:
            flash("Configure Telegram credentials in Settings first.", "error")
            return redirect(url_for("maintenance"))
        try:
            backup_path = create_backup_file(key)
            url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
            with open(backup_path, 'rb') as f:
                response = requests.post(url, data={'chat_id': chat_id, 'caption': f"📦 SecureVault Elite Backup\n📅 {now_iso()}"}, files={'document': f}, timeout=60)
            if response.status_code == 200:
                log_audit("telegram_backup", f"Vault exported to Telegram: {backup_path.name}")
                flash("Vault successfully backed up to Telegram Cloud!", "success")
            else:
                flash(f"Telegram API Error: {response.text}", "error")
        except Exception as e:
            flash(f"Cloud backup failed: {str(e)}", "error")
        return redirect(url_for("maintenance"))

    @app.route("/backup/github")
    def github_backup():
        key = require_key()
        gh_token = get_config_text("github_token", "").strip()
        gh_repo = get_config_text("github_repo", "").strip()
        if not gh_token or not gh_repo:
            flash("Configure GitHub credentials in Settings first.", "error")
            return redirect(url_for("maintenance"))
        try:
            backup_path = create_backup_file(key)
            content = base64.b64encode(backup_path.read_bytes()).decode('ascii')
            url = f"https://api.github.com/repos/{gh_repo}/contents/backups/{backup_path.name}"
            headers = {"Authorization": f"token {gh_token}", "Accept": "application/vnd.github.v3+json"}
            data = {"message": f"Vault Backup {now_iso()}", "content": content}
            response = requests.put(url, headers=headers, json=data, timeout=60)
            if response.status_code in [200, 201]:
                log_audit("github_backup", f"Vault pushed to GitHub: {backup_path.name}")
                flash("Vault successfully synced to GitHub!", "success")
            else:
                flash(f"GitHub API Error: {response.text}", "error")
        except Exception as e:
            flash(f"GitHub backup failed: {str(e)}", "error")
        return redirect(url_for("maintenance"))

    @app.route("/backup/dropbox")
    def dropbox_backup():
        key = require_key()
        dbx_token = get_config_text("dropbox_token", "").strip()
        if not dbx_token:
            flash("Configure Dropbox Token in Settings first.", "error")
            return redirect(url_for("maintenance"))
        try:
            backup_path = create_backup_file(key)
            url = "https://content.dropboxapi.com/2/files/upload"
            headers = {"Authorization": f"Bearer {dbx_token}", "Dropbox-API-Arg": json.dumps({"path": f"/SecureVault/{backup_path.name}", "mode": "add"}), "Content-Type": "application/octet-stream"}
            response = requests.post(url, headers=headers, data=backup_path.read_bytes(), timeout=60)
            if response.status_code == 200:
                log_audit("dropbox_backup", f"Vault uploaded to Dropbox: {backup_path.name}")
                flash("Vault successfully synced to Dropbox!", "success")
            else:
                flash(f"Dropbox API Error: {response.text}", "error")
        except Exception as e:
            flash(f"Dropbox backup failed: {str(e)}", "error")
        return redirect(url_for("maintenance"))

    @app.route("/settings", methods=["GET", "POST"])
    def settings():
        key = require_key()
        if request.method == "POST":
            if "password_hint" in request.form:
                set_config_value("password_hint", request.form.get("password_hint", "").strip())
            if "backup_location" in request.form:
                set_config_value("backup_location", request.form.get("backup_location", "").strip())
            if "session_timeout_seconds" in request.form:
                set_config_value("session_timeout_seconds", request.form.get("session_timeout_seconds", "900"))
            if "system_settings_submit" in request.form:
                set_config_value("auto_backup_enabled", "1" if request.form.get("auto_backup_enabled") else "0")
                set_config_value("lock_on_blur", "1" if request.form.get("lock_on_blur") else "0")
            if "telegram_bot_token" in request.form:
                set_config_value("telegram_bot_token", request.form.get("telegram_bot_token", "").strip())
            if "telegram_chat_id" in request.form:
                set_config_value("telegram_chat_id", request.form.get("telegram_chat_id", "").strip())
            if "github_token" in request.form:
                set_config_value("github_token", request.form.get("github_token", "").strip())
            if "github_repo" in request.form:
                set_config_value("github_repo", request.form.get("github_repo", "").strip())
            if "dropbox_token" in request.form:
                set_config_value("dropbox_token", request.form.get("dropbox_token", "").strip())
            log_audit("settings", "Security settings updated")
            flash("Configuration synchronized.", "success")
            return redirect(url_for("settings"))
        return render_template(
            "settings.html",
            password_hint=get_config_text("password_hint", ""),
            backup_location=get_config_text("backup_location", ""),
            session_timeout_seconds=str(get_session_timeout_seconds()),
            auto_backup_enabled=get_config_text("auto_backup_enabled", "1") == "1",
            lock_on_blur=get_config_text("lock_on_blur", "0") == "1",
            telegram_bot_token=get_config_text("telegram_bot_token", ""),
            telegram_chat_id=get_config_text("telegram_chat_id", ""),
            github_token=get_config_text("github_token", ""),
            github_repo=get_config_text("github_repo", ""),
            dropbox_token=get_config_text("dropbox_token", ""),
        )

    @app.route("/restore", methods=["POST"])
    def restore_backup():
        key = require_key()
        uploaded = request.files.get("backup_file")
        if not uploaded or not uploaded.filename:
            flash("Choose a .svault backup file first.", "error")
            return redirect(url_for("maintenance"))
        
        restore_type = request.form.get("restore_type", "password")
        legacy_password = request.form.get("legacy_password", "").strip()
        legacy_keyfile = request.files.get("legacy_keyfile")
        legacy_keyfile_data = legacy_keyfile.read() if legacy_keyfile else b""
        
        try:
            data = uploaded.read()
            restored_key = None
            if restore_type == "phrase":
                phrase = request.form.get("recovery_phrase", "").strip()
                if not phrase:
                    flash("Recovery phrase is required.", "error")
                    return redirect(url_for("maintenance"))
                restored_key = restore_backup_bytes(data, phrase)
            elif legacy_password:
                restored_key = restore_backup_bytes(data, password=legacy_password, keyfile_data=legacy_keyfile_data)
            else:
                restored_key = restore_backup_bytes(data, key)
            
            # Synchronize session key if it changed
            if restored_key and restored_key != key:
                token = secrets.token_urlsafe(32)
                ACTIVE_KEYS[token] = (restored_key, time.time())
                session.clear()
                session["vault_token"] = token
                log_audit("restore_session_sync", "Session key updated to match restored backup")
                
        except Exception as e:
            log_audit("restore_failed", f"Backup restore error: {str(e)}")
            flash(f"Restoration failed: {str(e)}", "error")
            return redirect(url_for("maintenance"))
        
        log_audit("restore", f"Backup restored: {Path(uploaded.filename).name}")
        flash("Backup restored successfully. Your vault has been updated.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/change-master-password", methods=["GET", "POST"])
    def change_master_password():
        old_key = require_key()
        requires_keyfile = get_config_text("requires_keyfile", "0") == "1"
        
        if request.method == "POST":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            
            # Keyfiles for both current and new
            current_keyfile = request.files.get("current_keyfile")
            current_keyfile_data = current_keyfile.read() if current_keyfile else b""
            
            new_keyfile = request.files.get("new_keyfile")
            new_keyfile_data = new_keyfile.read() if new_keyfile else b""
            
            try:
                check_key = derive_key(current_password, get_config_value("kdf_salt"), current_keyfile_data)
                decrypt_text(get_config_value("vault_check"), check_key)
            except (InvalidTag, ValueError):
                flash("Current master password or keyfile is incorrect.", "error")
                return render_template("change_master_password.html", requires_keyfile=requires_keyfile)
                
            if len(new_password) < 10:
                flash("Use at least 10 characters for the new master password.", "error")
                return render_template("change_master_password.html", requires_keyfile=requires_keyfile)
            if new_password != confirm:
                flash("New passwords do not match.", "error")
                return render_template("change_master_password.html", requires_keyfile=requires_keyfile)

            new_salt = os.urandom(16)
            new_key = derive_key(new_password, new_salt, new_keyfile_data)
            new_recovery_phrase = generate_recovery_phrase()
            new_recovery_salt = os.urandom(16)
            new_recovery_key = derive_key(new_recovery_phrase, new_recovery_salt)
            
            reencrypt_vault(old_key, new_key)
            set_config_value("kdf_salt", new_salt)
            set_config_value("vault_check", encrypt_text("securevault-ok", new_key))
            set_config_value("requires_keyfile", "1" if new_keyfile_data else "0")
            set_config_value("recovery_salt", new_recovery_salt)
            set_config_value("recovery_check", encrypt_text("securevault-recovery-ok", new_recovery_key))
            set_config_value("recovery_wrapped_key", wrap_key(new_key, new_recovery_key))

            token = secrets.token_urlsafe(32)
            ACTIVE_KEYS.clear()
            ACTIVE_KEYS[token] = (new_key, time.time())
            session.clear()
            session["vault_token"] = token
            session["recovery_phrase_once"] = new_recovery_phrase
            log_audit("master_password_change", "Master password changed")
            flash("Master password changed. Print or save the new recovery kit.", "success")
            return redirect(url_for("recovery_kit"))
            
        return render_template("change_master_password.html", requires_keyfile=requires_keyfile)

    @app.route("/recovery-kit")
    def recovery_kit():
        require_key()
        recovery_phrase = session.pop("recovery_phrase_once", None)
        try:
            salt_hex = get_config_value("kdf_salt").hex()
        except:
            salt_hex = "Not available"

        try:
            recovery_salt_hex = get_config_value("recovery_salt").hex()
        except:
            recovery_salt_hex = "Not available"
            
        return render_template(
            "recovery_kit.html",
            recovery_phrase=recovery_phrase,
            vault_salt=salt_hex,
            recovery_salt=recovery_salt_hex,
            created_at=now_iso(),
            developer_name="MANORANJAN",
            developer_github="https://github.com/manoranjan2050",
        )

    @app.route("/generate-recovery-kit", methods=["POST"])
    def generate_recovery_kit():
        key = require_key()
        recovery_phrase = generate_recovery_phrase()
        recovery_salt = os.urandom(16)
        recovery_key = derive_key(recovery_phrase, recovery_salt)
        set_config_value("recovery_salt", recovery_salt)
        set_config_value("recovery_check", encrypt_text("securevault-recovery-ok", recovery_key))
        set_config_value("recovery_wrapped_key", wrap_key(key, recovery_key))
        session["recovery_phrase_once"] = recovery_phrase
        log_audit("recovery_kit", "New recovery kit generated")
        flash("New recovery kit generated. Print or save it now.", "success")
        return redirect(url_for("recovery_kit"))

    @app.route("/health")
    def health():
        key = require_key()
        report = vault_health_report(key)
        return render_template("health.html", report=report)

    @app.route("/audit-log")
    def audit_log():
        require_key()
        rows = fetch_all("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 150")
        return render_template("audit_log.html", entries=rows)

    @app.route("/trash")
    def trash():
        key = require_key()
        rows = fetch_all("SELECT * FROM trash_items ORDER BY deleted_at DESC")
        entries = []
        for row in rows:
            entries.append({
                "id": row["id"],
                "item_type": row["item_type"],
                "title": row["title"],
                "deleted_at": row["deleted_at"],
            })
        return render_template("trash.html", entries=entries)

    @app.route("/trash/<int:item_id>/restore", methods=["POST"])
    def restore_trash(item_id: int):
        key = require_key()
        row = fetch_one("SELECT * FROM trash_items WHERE id = ?", (item_id,))
        if row is None:
            flash("Trash item not found.", "error")
            return redirect(url_for("trash"))
        try:
            restore_trash_item(key, row)
        except RuntimeError:
            flash("Restore failed because the encrypted file is missing.", "error")
            return redirect(url_for("trash"))
        execute("DELETE FROM trash_items WHERE id = ?", (item_id,))
        log_audit("trash_restore", f"Restored {row['item_type']}: {row['title']}")
        flash("Item restored.", "success")
        return redirect(url_for("trash"))

    @app.route("/trash/<int:item_id>/purge", methods=["POST"])
    def purge_trash(item_id: int):
        key = require_key()
        row = fetch_one("SELECT * FROM trash_items WHERE id = ?", (item_id,))
        if row:
            payload = decrypt_json(row["encrypted_payload"], key)
            if row["item_type"] == "document":
                stored_name = payload.get("stored_name", "")
                file_path = get_files_dir() / stored_name
                if stored_name and file_path.exists():
                    file_path.unlink()
            execute("DELETE FROM trash_items WHERE id = ?", (item_id,))
            log_audit("trash_purge", f"Purged {row['item_type']}: {row['title']}")
        flash("Item permanently deleted.", "success")
        return redirect(url_for("trash"))

    @app.route("/passwords/<int:entry_id>/history")
    def password_history(entry_id: int):
        key = require_key()
        password = fetch_one("SELECT * FROM passwords WHERE id = ?", (entry_id,))
        if password is None:
            flash("Password entry not found.", "error")
            return redirect(url_for("passwords"))
        rows = fetch_all("SELECT * FROM password_history WHERE password_id = ? ORDER BY changed_at DESC", (entry_id,))
        entries = []
        for row in rows:
            item = dict(row)
            item["old_password"] = decrypt_text(row["encrypted_password"], key)
            item["old_notes"] = decrypt_text(row["encrypted_notes"], key)
            entries.append(item)
        return render_template("password_history.html", password=password, entries=entries)

    @app.route("/lock")
    def lock():
        token = session.get("vault_token")
        if token:
            ACTIVE_KEYS.pop(token, None)
        session.clear()
        flash("Vault locked.", "info")
        return redirect(url_for("login"))

    @app.route("/logout")
    def logout():
        return redirect(url_for("lock"))

    @app.route("/totp/import-qr", methods=["POST"])
    def import_totp_qr():
        key = require_key()
        uploaded = request.files.get("qr_code")
        if not uploaded or not uploaded.filename:
            flash("Choose a QR code image first.", "error")
            return redirect(url_for("totp_accounts"))

        try:
            # Read image and decode QR
            file_bytes = np.frombuffer(uploaded.read(), np.uint8)
            img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
            if img is None:
                flash("Could not read image file.", "error")
                return redirect(url_for("totp_accounts"))

            detector = cv2.QRCodeDetector()
            qr_data, _, _ = detector.detectAndDecode(img)
            
            if not qr_data:
                flash("No QR code detected in image.", "error")
                return redirect(url_for("totp_accounts"))

            count = 0
            # Handle Migration URL
            if qr_data.startswith("otpauth-migration://"):
                parsed = urlparse(qr_data)
                params = parse_qs(parsed.query)
                data_b64 = params.get("data", [""])[0]
                
                accounts = decode_migration_payload(data_b64)
                for acc in accounts:
                    save_totp_account(acc, key)
                    count += 1
                
                flash(f"Successfully imported {count} accounts from migration QR.", "success")
            
            # Handle Standard TOTP URL
            elif qr_data.startswith("otpauth://"):
                acc = parse_standard_otp_url(qr_data)
                if acc:
                    save_totp_account(acc, key)
                    flash("Account imported from QR code.", "success")
                else:
                    flash("Invalid TOTP URL in QR code.", "error")
            
            else:
                flash("QR code does not contain a valid TOTP setup link.", "error")

        except Exception as e:
            flash(f"Import failed: {str(e)}", "error")

        return redirect(url_for("totp_accounts"))

    def save_totp_account(acc, key):
        now = now_iso()
        execute(
            """
            INSERT INTO totp_accounts
                (issuer, account_name, encrypted_secret, digits, period, algorithm, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                acc.get('issuer', '').strip(),
                acc.get('name', '').strip(),
                encrypt_text(acc['secret'], key),
                acc.get('digits', 6),
                acc.get('period', 30),
                acc.get('algorithm', 'SHA1'),
                acc.get('notes', '').strip(),
                now,
                now,
            ),
        )

    return app


def decode_migration_payload(data_b64: str) -> list[dict]:
    # Proto Varint Reader
    def read_varint(buffer, offset):
        res, shift = 0, 0
        while True:
            b = buffer[offset]
            res |= (b & 0x7F) << shift
            offset += 1
            if not (b & 0x80): break
            shift += 7
        return res, offset

    # Proto Field Parser
    def parse_params(data):
        acc = {'secret': '', 'name': '', 'issuer': '', 'algorithm': 'SHA1', 'digits': 6, 'period': 30}
        pos = 0
        while pos < len(data):
            tag_byte = data[pos]
            tag, wire = tag_byte >> 3, tag_byte & 0x07
            pos += 1
            if tag == 1 and wire == 2: # secret
                L, pos = read_varint(data, pos)
                acc['secret'] = base64.b32encode(data[pos:pos+L]).decode('ascii').replace('=', '')
                pos += L
            elif tag == 2 and wire == 2: # name
                L, pos = read_varint(data, pos)
                acc['name'] = data[pos:pos+L].decode('utf-8')
                pos += L
            elif tag == 3 and wire == 2: # issuer
                L, pos = read_varint(data, pos)
                acc['issuer'] = data[pos:pos+L].decode('utf-8')
                pos += L
            elif tag == 4 and wire == 0: # algo
                v, pos = read_varint(data, pos)
                acc['algorithm'] = {1:'SHA1', 2:'SHA256', 3:'SHA512', 4:'MD5'}.get(v, 'SHA1')
            elif tag == 5 and wire == 0: # digits
                v, pos = read_varint(data, pos)
                acc['digits'] = 8 if v == 2 else 6
            else: # Skip
                if wire == 0: _, pos = read_varint(data, pos)
                elif wire == 2: L, pos = read_varint(data, pos); pos += L
        return acc

    try:
        raw = base64.b64decode(unquote(data_b64))
        accounts = []
        pos = 0
        while pos < len(raw):
            tag_byte = raw[pos]
            tag, wire = tag_byte >> 3, tag_byte & 0x07
            pos += 1
            if tag == 1 and wire == 2:
                L, pos = read_varint(raw, pos)
                accounts.append(parse_params(raw[pos:pos+L]))
                pos += L
            else:
                if wire == 0: _, pos = read_varint(raw, pos)
                elif wire == 2: L, pos = read_varint(raw, pos); pos += L
        return accounts
    except: return []


def parse_standard_otp_url(url: str) -> dict | None:
    try:
        parsed = urlparse(url)
        if parsed.scheme != 'otpauth': return None
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        label = unquote(parsed.path[1:])
        issuer, name = label.split(':', 1) if ':' in label else ('', label)
        return {
            'secret': params.get('secret', ''),
            'name': name.strip(),
            'issuer': params.get('issuer', issuer).strip(),
            'digits': int(params.get('digits', 6)),
            'period': int(params.get('period', 30)),
            'algorithm': params.get('algorithm', 'SHA1').upper()
        }
    except: return None


def load_or_create_flask_secret() -> str:
    secret_path = get_vault_paths()["flask_secret"]
    if secret_path.exists():
        return secret_path.read_text(encoding="utf-8")
    secret = secrets.token_urlsafe(48)
    secret_path.write_text(secret, encoding="utf-8")
    return secret


def init_db() -> None:
    with connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                website TEXT,
                username TEXT,
                encrypted_password TEXT NOT NULL,
                encrypted_notes TEXT NOT NULL,
                tags TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS totp_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issuer TEXT NOT NULL,
                account_name TEXT NOT NULL,
                encrypted_secret TEXT NOT NULL,
                digits INTEGER NOT NULL DEFAULT 6,
                period INTEGER NOT NULL DEFAULT 30,
                algorithm TEXT NOT NULL DEFAULT 'SHA1',
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secure_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                encrypted_content TEXT NOT NULL,
                category TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                mime_type TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS financial_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_type TEXT NOT NULL,
                encrypted_data TEXT NOT NULL,
                favorite INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS trash_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_type TEXT NOT NULL,
                title TEXT NOT NULL,
                encrypted_payload TEXT NOT NULL,
                deleted_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS shared_messages (
                id TEXT PRIMARY KEY,
                encrypted_content TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                view_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                website TEXT,
                username TEXT,
                encrypted_password TEXT NOT NULL,
                encrypted_notes TEXT NOT NULL,
                tags TEXT,
                changed_at TEXT NOT NULL
            );
            """
        )
        ensure_column(db, "financial_accounts", "favorite", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(db, "documents", "mime_type", "TEXT")
        ensure_column(db, "documents", "category", "TEXT DEFAULT 'Uncategorized'")
        ensure_column(db, "passwords", "email_id", "TEXT")
        ensure_column(db, "passwords", "mobile_no", "TEXT")
        ensure_column(db, "password_history", "email_id", "TEXT")
        ensure_column(db, "password_history", "mobile_no", "TEXT")


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(get_vault_paths()["db"])
    db.row_factory = sqlite3.Row
    return db


def ensure_column(db: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = [row["name"] for row in db.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in columns:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def execute(sql: str, params: tuple[Any, ...] = ()) -> None:
    with connect() as db:
        db.execute(sql, params)
        db.commit()


def fetch_one(sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
    with connect() as db:
        return db.execute(sql, params).fetchone()


def fetch_all(sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    with connect() as db:
        return db.execute(sql, params).fetchall()


def query_scalar(sql: str, params: tuple[Any, ...] = ()) -> int:
    row = fetch_one(sql, params)
    return int(row[0]) if row else 0


def is_configured() -> bool:
    return fetch_one("SELECT 1 FROM config WHERE key = 'vault_check'") is not None


def set_config_value(key: str, value: bytes | str) -> None:
    if isinstance(value, str):
        value = value.encode("utf-8")
    execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, value))


def get_config_value(key: str) -> bytes:
    row = fetch_one("SELECT value FROM config WHERE key = ?", (key,))
    if row is None:
        raise ValueError(f"Missing config value: {key}")
    return bytes(row["value"])


def get_config_text(key: str, default: str = "") -> str:
    row = fetch_one("SELECT value FROM config WHERE key = ?", (key,))
    if row is None:
        return default
    return bytes(row["value"]).decode("utf-8")


def get_session_timeout_seconds() -> int:
    try:
        value = int(get_config_text("session_timeout_seconds", str(DEFAULT_SESSION_TIMEOUT_SECONDS)))
    except ValueError:
        return DEFAULT_SESSION_TIMEOUT_SECONDS
    allowed = {300, 900, 1800, 3600}
    return value if value in allowed else DEFAULT_SESSION_TIMEOUT_SECONDS


def derive_key(password: str, salt: bytes, keyfile_data: bytes = b"") -> bytes:
    if not password:
        raise ValueError("Password is required")
    
    secret = password.encode("utf-8")
    if keyfile_data:
        # Incorporate SHA-256 hash of keyfile into the secret
        secret += hashlib.sha256(keyfile_data).digest()
        
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.ID,
    )


def encrypt_text(value: str, key: bytes) -> str:
    return base64.urlsafe_b64encode(encrypt_bytes(value.encode("utf-8"), key)).decode("ascii")


def decrypt_text(value: str | bytes, key: bytes) -> str:
    if isinstance(value, bytes):
        value = value.decode("ascii")
    return decrypt_bytes(base64.urlsafe_b64decode(value.encode("ascii")), key).decode("utf-8")


def encrypt_json(value: dict[str, str], key: bytes) -> str:
    return encrypt_text(json.dumps(value, ensure_ascii=True), key)


def decrypt_json(value: str | bytes, key: bytes) -> dict[str, str]:
    data = json.loads(decrypt_text(value, key))
    return {str(item_key): str(item_value) for item_key, item_value in data.items()}


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, data, None)
    return nonce + encrypted


def decrypt_bytes(data: bytes, key: bytes) -> bytes:
    if len(data) < 13:
        raise ValueError("Encrypted data is invalid")
    nonce = data[:12]
    encrypted = data[12:]
    return AESGCM(key).decrypt(nonce, encrypted, None)


def get_active_key() -> bytes | None:
    token = session.get("vault_token")
    if not token:
        return None
    record = ACTIVE_KEYS.get(token)
    if not record:
        return None
    key, last_seen = record
    if time.time() - last_seen > get_session_timeout_seconds():
        ACTIVE_KEYS.pop(token, None)
        return None
    ACTIVE_KEYS[token] = (key, time.time())
    return key


def require_key() -> bytes:
    key = get_active_key()
    if key is None:
        raise RuntimeError("Vault is locked")
    return key


def now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def financial_form_data(type_config: dict[str, Any]) -> dict[str, str]:
    return {
        field_name: request.form.get(field_name, "").strip()
        for field_name, _label, _field_type in type_config["fields"]
    }


def financial_title(account_type: str, data: dict[str, str]) -> str:
    for field_name in FINANCIAL_TITLE_FIELDS.get(account_type, ()):
        if data.get(field_name):
            return data[field_name]
    return FINANCIAL_ACCOUNT_TYPES.get(account_type, FINANCIAL_ACCOUNT_TYPES["bank"])["label"]


def financial_subtitle(account_type: str, data: dict[str, str]) -> str:
    for field_name in FINANCIAL_SUBTITLE_FIELDS.get(account_type, ()):
        if data.get(field_name):
            return data[field_name]
    label = FINANCIAL_ACCOUNT_TYPES.get(account_type, FINANCIAL_ACCOUNT_TYPES["bank"])["label"]
    return f"Private {label.lower()} record"


def normalize_totp_secret(value: str) -> str:
    value = value.strip()
    if value.lower().startswith("otpauth://"):
        parsed = urlparse(value)
        query = parse_qs(parsed.query)
        value = query.get("secret", [""])[0]
    return value.replace(" ", "").upper()


def is_valid_totp_secret(secret: str) -> bool:
    if not secret:
        return False
    try:
        # Add padding if missing (Base32 length must be a multiple of 8)
        missing_padding = len(secret) % 8
        if missing_padding:
            secret += "=" * (8 - missing_padding)
        base64.b32decode(secret, casefold=True)
    except Exception:
        return False
    return True


def generate_totp(secret: str, digits: int = 6, period: int = 30, algorithm: str = "SHA1") -> str:
    secret = normalize_totp_secret(secret)
    missing_padding = len(secret) % 8
    if missing_padding:
        secret += "=" * (8 - missing_padding)
    
    key = base64.b32decode(secret, casefold=True)
    counter = int(time.time()) // int(period)
    digest_name = algorithm.lower()
    digest = getattr(hashlib, digest_name, hashlib.sha1)
    message = struct.pack(">Q", counter)
    hmac_hash = hmac.new(key, message, digest).digest()
    offset = hmac_hash[-1] & 0x0F
    code = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** int(digits))).zfill(int(digits))


def import_password_csv(data: bytes, key: bytes) -> int:
    text = data.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV has no header")
    imported = 0
    for row in reader:
        lowered = {str(k).strip().lower(): (v or "").strip() for k, v in row.items()}
        title = first_csv_value(lowered, "name", "title", "website", "url")
        password = first_csv_value(lowered, "password", "pass")
        if not password:
            continue
        now = now_iso()
        execute(
            """
            INSERT INTO passwords
                (title, website, username, encrypted_password, encrypted_notes, tags, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title or "Imported Password",
                first_csv_value(lowered, "url", "website", "login_uri", "login url"),
                first_csv_value(lowered, "username", "login", "email", "user"),
                encrypt_text(password, key),
                encrypt_text(first_csv_value(lowered, "notes", "note", "extra"), key),
                first_csv_value(lowered, "folder", "tags", "category") or "Imported",
                now,
                now,
            ),
        )
        imported += 1
    return imported


def first_csv_value(row: dict[str, str], *names: str) -> str:
    for name in names:
        value = row.get(name)
        if value:
            return value
    return ""


def guess_mime_type(filename: str) -> str:
    mime_type, _encoding = mimetypes.guess_type(filename)
    return mime_type or "application/octet-stream"


def is_previewable_mime(mime_type: str) -> bool:
    return mime_type == "application/pdf" or mime_type.startswith("image/")


def register_failed_login() -> None:
    count = int(get_config_text("failed_login_count", "0") or "0") + 1
    set_config_value("failed_login_count", str(count))
    if count >= 5:
        set_config_value("login_locked_until", str(int(time.time() + 300)))
        log_audit("login_lockout", "Login locked for 5 minutes after failed attempts")


def reset_failed_logins() -> None:
    set_config_value("failed_login_count", "0")
    set_config_value("login_locked_until", "0")


def get_login_locked_until() -> float:
    try:
        return float(get_config_text("login_locked_until", "0") or "0")
    except ValueError:
        return 0


def save_password_history(key: bytes, row: sqlite3.Row) -> None:
    execute(
        """
        INSERT INTO password_history
            (password_id, title, website, username, email_id, mobile_no, encrypted_password, encrypted_notes, tags, changed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            row["id"],
            row["title"],
            row["website"],
            row["username"],
            row.get("email_id", ""),
            row.get("mobile_no", ""),
            row["encrypted_password"],
            row["encrypted_notes"],
            row["tags"],
            now_iso(),
        ),
    )
    log_audit("password_history", f"Saved previous version: {row['title']}")


def move_to_trash(key: bytes, item_type: str, title: str, payload: dict[str, Any]) -> None:
    clean_payload = {}
    for item_key, item_value in payload.items():
        clean_payload[str(item_key)] = "" if item_value is None else str(item_value)
    execute(
        """
        INSERT INTO trash_items (item_type, title, encrypted_payload, deleted_at)
        VALUES (?, ?, ?, ?)
        """,
        (item_type, title or item_type, encrypt_json(clean_payload, key), now_iso()),
    )
    log_audit("trash", f"Moved {item_type} to trash: {title}")


def restore_trash_item(key: bytes, row: sqlite3.Row) -> None:
    payload = decrypt_json(row["encrypted_payload"], key)
    now = now_iso()
    item_type = row["item_type"]
    if item_type == "password":
        execute(
            """
            INSERT INTO passwords
                (title, website, username, email_id, mobile_no, encrypted_password, encrypted_notes, tags, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.get("title", ""),
                payload.get("website", ""),
                payload.get("username", ""),
                payload.get("email_id", ""),
                payload.get("mobile_no", ""),
                payload.get("encrypted_password", ""),
                payload.get("encrypted_notes", ""),
                payload.get("tags", ""),
                payload.get("created_at", now),
                now,
            ),
        )
        return
    if item_type == "secure_note":
        execute(
            """
            INSERT INTO secure_notes (title, encrypted_content, category, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                payload.get("title", ""),
                payload.get("encrypted_content", ""),
                payload.get("category", ""),
                payload.get("created_at", now),
                now,
            ),
        )
        return
    if item_type == "financial_account":
        execute(
            """
            INSERT INTO financial_accounts (account_type, encrypted_data, favorite, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                payload.get("account_type", "bank"),
                payload.get("encrypted_data", ""),
                int(payload.get("favorite", "0") or "0"),
                payload.get("created_at", now),
                now,
            ),
        )
        return
    if item_type == "totp":
        execute(
            """
            INSERT INTO totp_accounts
                (issuer, account_name, encrypted_secret, digits, period, algorithm, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.get("issuer", ""),
                payload.get("account_name", ""),
                payload.get("encrypted_secret", ""),
                int(payload.get("digits", "6") or "6"),
                int(payload.get("period", "30") or "30"),
                payload.get("algorithm", "SHA1"),
                payload.get("notes", ""),
                payload.get("created_at", now),
                now,
            ),
        )
        return
    if item_type == "document":
        stored_name = payload.get("stored_name", "")
        if stored_name and not (get_files_dir() / stored_name).exists():
            raise RuntimeError("Encrypted file is missing")
        execute(
            """
            INSERT INTO documents (filename, stored_name, file_size, mime_type, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                payload.get("filename", ""),
                stored_name,
                int(payload.get("file_size", "0") or "0"),
                payload.get("mime_type", "") or guess_mime_type(payload.get("filename", "")),
                payload.get("created_at", now),
            ),
        )


def generate_recovery_phrase() -> str:
    return "SV-" + "-".join(secrets.token_hex(2).upper() for _ in range(8))


def wrap_key(vault_key: bytes, recovery_key: bytes) -> str:
    return base64.urlsafe_b64encode(encrypt_bytes(vault_key, recovery_key)).decode("ascii")


def unwrap_key(value: str | bytes, recovery_key: bytes) -> bytes:
    if isinstance(value, bytes):
        value = value.decode("ascii")
    key = decrypt_bytes(base64.urlsafe_b64decode(value.encode("ascii")), recovery_key)
    if len(key) != 32:
        raise ValueError("Recovered key is invalid")
    return key


def form_checkbox(name: str) -> int:
    return 1 if request.form.get(name) else 0


def create_backup_file(key: bytes, backup_dir: Path | None = None) -> Path:
    backup_dir = backup_dir or get_backup_directory()
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / f"securevault_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.svault"
    
    salt = get_config_value("kdf_salt")
    
    # Include recovery metadata for "Restore with Phrase"
    rec_salt = get_config_value("recovery_salt")
    rec_wrapped = get_config_value("recovery_wrapped_key")
    
    if not rec_salt or not rec_wrapped:
        # Fallback if metadata is missing (should not happen in Elite v2.2.1+)
        rec_salt = b"\x00" * 16
        rec_wrapped = b""

    payload = encrypt_bytes(create_backup_zip_bytes(), key)
    
    # Format: MAGIC(4) + KDF_SALT(16) + REC_SALT(16) + WRAPPED_LEN(4) + WRAPPED_DATA(N) + PAYLOAD
    wrapped_bytes = rec_wrapped if isinstance(rec_wrapped, bytes) else rec_wrapped.encode("ascii")
    header = struct.pack("<4s16s16sI", BACKUP_MAGIC, salt, rec_salt, len(wrapped_bytes))
    
    backup_path.write_bytes(header + wrapped_bytes + payload)
    return backup_path


def create_backup_zip_bytes() -> bytes:
    zip_buffer = io.BytesIO()
    with ZipFile(zip_buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.write(get_db_path(), "data/vault.db")
        if get_flask_secret_path().exists():
            archive.write(get_flask_secret_path(), "data/flask.secret")
        for file_path in get_files_dir().glob("*"):
            if file_path.is_file() and file_path.name != ".gitkeep":
                archive.write(file_path, f"encrypted_files/{file_path.name}")
    return zip_buffer.getvalue()


def get_backup_directory() -> Path:
    configured = get_config_text("backup_location", "").strip()
    if configured:
        return Path(configured).expanduser()
    return get_backup_dir()


def run_auto_backup(key: bytes) -> None:
    if get_config_text("auto_backup_enabled", "1") != "1":
        return
    today = datetime.now().strftime("%Y-%m-%d")
    if get_config_text("last_auto_backup_date", "") == today:
        return
    try:
        backup_path = create_backup_file(key)
    except OSError:
        log_audit("auto_backup_failed", "Auto backup failed")
        return
    set_config_value("last_auto_backup_date", today)
    log_audit("auto_backup", f"Auto backup created: {backup_path.name}")


def restore_backup_bytes(data: bytes, key_or_phrase: str | bytes = None, password: str = None, keyfile_data: bytes = b"") -> bytes:
    vault_key = None
    
    # 1. Handle Modern Format (Starts with MAGIC)
    if data.startswith(BACKUP_MAGIC):
        try:
            # Read header: MAGIC(4), KDF_SALT(16), REC_SALT(16), WRAPPED_LEN(4)
            if len(data) < 40: raise ValueError("Backup file is too small or corrupted.")
            magic, kdf_salt, rec_salt, wrapped_len = struct.unpack("<4s16s16sI", data[:40])
            
            wrapped_key = data[40:40+wrapped_len]
            encrypted_payload = data[40+wrapped_len:]
            
            if not encrypted_payload: raise ValueError("Backup file contains no payload data.")
        except (struct.error, ValueError):
            # Fallback for simple SVLT+SALT format (pre-v2.2.1)
            kdf_salt = data[4:20]
            encrypted_payload = data[20:]
            wrapped_key = b""
            rec_salt = None

        if password:
            # Derived from a specific provided password (e.g., legacy restore)
            vault_key = derive_key(password, kdf_salt, keyfile_data)
        elif isinstance(key_or_phrase, bytes):
            # Provided direct master key (current session)
            vault_key = key_or_phrase
        elif isinstance(key_or_phrase, str):
            # Provided recovery phrase
            if not wrapped_key or rec_salt is None or rec_salt == b"\x00" * 16:
                raise ValueError("This backup does not contain recovery metadata. You must restore it using the original Master Password.")
            try:
                recovery_key = derive_key(key_or_phrase, rec_salt)
                vault_key = unwrap_key(wrapped_key, recovery_key)
            except Exception:
                raise ValueError("Recovery phrase is incorrect for this backup.")
    else:
        # 2. Handle Legacy Format (No Magic)
        if password:
            # We don't have a salt in the header for no-magic legacy files? 
            # Actually, most early formats either had no salt or the salt was known.
            # But the 'else' case for MAGIC-less backups usually means very old or invalid.
            # If the user provides a password, we'll try to use a dummy or let it fail.
            raise ValueError("Unsupported legacy backup format (Missing MAGIC header).")
            
        if isinstance(key_or_phrase, str):
            raise ValueError("Recovery phrase restore is only supported for modern .svault backups.")
        vault_key = key_or_phrase
        encrypted_payload = data
        
    if not vault_key:
        raise ValueError("No valid decryption key provided.")
        
    try:
        decrypted = decrypt_bytes(encrypted_payload, vault_key)
    except Exception:
        raise ValueError("Decryption failed. Incorrect master password, keyfile, or corrupted backup.")

    with ZipFile(io.BytesIO(decrypted), "r") as archive:
        names = archive.namelist()
        if "data/vault.db" not in names:
            raise ValueError("Backup archive is invalid (missing database)")
        
        # Verify file list for safety
        for name in names:
            if not (name == "data/vault.db" or name == "data/flask.secret" or name.startswith("encrypted_files/")):
                raise ValueError(f"Backup contains unexpected file: {name}")

        try:
            # Restore database
            db_content = archive.read("data/vault.db")
            get_db_path().write_bytes(db_content)
            
            if "data/flask.secret" in names:
                get_flask_secret_path().write_bytes(archive.read("data/flask.secret"))

            # Clean and restore encrypted files
            for file_path in get_files_dir().glob("*"):
                if file_path.is_file() and file_path.name != ".gitkeep":
                    file_path.unlink()
            
            for name in names:
                if name.startswith("encrypted_files/") and not name.endswith("/"):
                    target = get_files_dir() / Path(name).name
                    target.write_bytes(archive.read(name))
        except PermissionError:
            raise RuntimeError("Database file is locked. Please close any other tabs/apps and try again.")
        except Exception as e:
            raise RuntimeError(f"File system error during restore: {str(e)}")
            
    init_db()
    return vault_key


def reencrypt_vault(old_key: bytes, new_key: bytes) -> None:
    for row in fetch_all("SELECT * FROM passwords"):
        execute(
            """
            UPDATE passwords
            SET encrypted_password = ?, encrypted_notes = ?
            WHERE id = ?
            """,
            (
                encrypt_text(decrypt_text(row["encrypted_password"], old_key), new_key),
                encrypt_text(decrypt_text(row["encrypted_notes"], old_key), new_key),
                row["id"],
            ),
        )

    for row in fetch_all("SELECT * FROM secure_notes"):
        execute(
            "UPDATE secure_notes SET encrypted_content = ? WHERE id = ?",
            (encrypt_text(decrypt_text(row["encrypted_content"], old_key), new_key), row["id"]),
        )

    for row in fetch_all("SELECT * FROM financial_accounts"):
        execute(
            "UPDATE financial_accounts SET encrypted_data = ? WHERE id = ?",
            (encrypt_text(decrypt_text(row["encrypted_data"], old_key), new_key), row["id"]),
        )

    for row in fetch_all("SELECT * FROM totp_accounts"):
        execute(
            "UPDATE totp_accounts SET encrypted_secret = ? WHERE id = ?",
            (encrypt_text(decrypt_text(row["encrypted_secret"], old_key), new_key), row["id"]),
        )

    for row in fetch_all("SELECT * FROM trash_items"):
        execute(
            "UPDATE trash_items SET encrypted_payload = ? WHERE id = ?",
            (encrypt_text(decrypt_text(row["encrypted_payload"], old_key), new_key), row["id"]),
        )

    for row in fetch_all("SELECT * FROM password_history"):
        execute(
            """
            UPDATE password_history
            SET encrypted_password = ?, encrypted_notes = ?
            WHERE id = ?
            """,
            (
                encrypt_text(decrypt_text(row["encrypted_password"], old_key), new_key),
                encrypt_text(decrypt_text(row["encrypted_notes"], old_key), new_key),
                row["id"],
            ),
        )

    for row in fetch_all("SELECT * FROM documents"):
        file_path = get_files_dir() / row["stored_name"]
        if file_path.exists():
            plain = decrypt_bytes(file_path.read_bytes(), old_key)
            file_path.write_bytes(encrypt_bytes(plain, new_key))


def vault_health_report(key: bytes) -> dict[str, Any]:
    rows = fetch_all("SELECT * FROM passwords")
    passwords = []
    for row in rows:
        password = decrypt_text(row["encrypted_password"], key)
        passwords.append({"row": row, "password": password})

    password_values = [item["password"] for item in passwords]
    duplicates = len(password_values) - len(set(password_values))
    weak = [item for item in passwords if password_score(item["password"]) < 3]
    old = [item for item in passwords if is_old_date(item["row"]["updated_at"])]
    missing_2fa = [
        item for item in passwords
        if "2fa" not in (item["row"]["tags"] or "").lower()
        and "totp" not in (item["row"]["tags"] or "").lower()
    ]
    return {
        "total_passwords": len(passwords),
        "weak_passwords": len(weak),
        "duplicate_passwords": duplicates,
        "old_passwords": len(old),
        "missing_2fa": len(missing_2fa),
        "documents": query_scalar("SELECT COUNT(*) FROM documents"),
        "records": query_scalar("SELECT COUNT(*) FROM financial_accounts"),
    }


def password_score(password: str) -> int:
    score = 0
    score += len(password) >= 12
    score += any(char.islower() for char in password)
    score += any(char.isupper() for char in password)
    score += any(char.isdigit() for char in password)
    score += any(not char.isalnum() for char in password)
    return int(score)


def is_old_date(value: str) -> bool:
    try:
        updated_at = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    return (datetime.now() - updated_at).days >= 180


def log_audit(event_type: str, message: str) -> None:
    try:
        execute(
            "INSERT INTO audit_logs (event_type, message, created_at) VALUES (?, ?, ?)",
            (event_type, message, now_iso()),
        )
    except sqlite3.Error:
        pass


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
