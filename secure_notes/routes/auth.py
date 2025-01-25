import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, send_from_directory
from flask_login import login_required, login_user, logout_user, current_user
from ..forms import RegistrationForm, LoginForm, ForgotPasswordForm, ResetPasswordForm
from .. import db, User, FailedLoginAttempt
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime, timedelta
from time import sleep
import os
from sqlalchemy.exc import IntegrityError
import pyotp
from qrcode import QRCode
from itsdangerous import URLSafeTimedSerializer
import smtplib
from email.message import EmailMessage
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

LOGIN_ATTEMPT_LIMIT = int(os.getenv('LOGIN_ATTEMPT_LIMIT', 5))
LOGIN_DELAY = int(os.getenv('LOGIN_DELAY', 1))
SECRET_KEY = os.getenv('SECRET_KEY', 'your_default_secret_key')
MAIL_SERVER = os.getenv('MAIL_SERVER')
MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
MAIL_FROM = os.getenv('MAIL_FROM')

# Global encryption key for notes, must be the same as in notes.py
GLOBAL_ENCRYPTION_KEY = os.getenv('GLOBAL_ENCRYPTION_KEY', '16bytesSecretKey').encode()
IV = b'16bytesIV1234567'  # Initialization vector for AES

s = URLSafeTimedSerializer(SECRET_KEY)


def generate_keys(password):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    # Szyfrowanie klucza prywatnego hasłem użytkownika
    salt = secrets.token_hex(16)
    encrypted_key = encrypt_key(private_key, password, salt)

    # Konwersja klucza publicznego na tekst
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return public_pem, encrypted_key, salt


def encrypt_key(private_key, password, salt):
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    print(f"Encrypt Key Salt: {salt}")
    salt = salt.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(key)
    )

    return private_pem.decode()


# Decrypt the encrypted private key using password

def decrypt_key(encrypted_key, password, key_salt):
    print(f"Decrypt Key Salt: {key_salt}")
    try:
        key_salt = key_salt.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=key_salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        # Ensure the encrypted_key is properly padded
        missing_padding = len(encrypted_key) % 4
        if missing_padding:
            encrypted_key += '=' * (4 - missing_padding)

        # Decrypt the private key using the derived key
        private_key = serialization.load_pem_private_key(
            encrypted_key.encode(),
            password=key,
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        print(f"Error during private key decryption: {e}")
        return None


def send_reset_email(user):
    token = s.dumps(user.username, salt='reset-password')
    reset_url = url_for('auth.reset_password', token=token, _external=True)

    msg = EmailMessage()
    msg.set_content(f"Aby zresetować hasło kliknij w link:\n{reset_url}")
    msg['Subject'] = 'Reset hasła'
    msg['From'] = MAIL_FROM
    msg['To'] = user.email

    try:
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
            server.connect(MAIL_SERVER, MAIL_PORT)
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)
            flash(f'Link resetujący hasło został wysłany na adres email {user.email}', 'success')
    except Exception as e:
        print(e)
        flash("Nie udało się wysłać emaila, spróbuj ponownie później", "danger")


def send_new_login_email(user, ip_address):
    msg = EmailMessage()
    msg.set_content(f"Z Twojego konta zalogowano się z nowego adresu IP: {ip_address}")
    msg['Subject'] = 'Nowe logowanie'
    msg['From'] = MAIL_FROM
    msg['To'] = user.email
    try:
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
            server.connect(MAIL_SERVER, MAIL_PORT)
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)
            flash(f'Powiadomienie o logowaniu z nowego IP zostało wysłane na adres email {user.email}', 'success')
    except Exception as e:
        print(e)
        flash("Nie udało się wysłać emaila, spróbuj ponownie później", "danger")


@auth_bp.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
            return redirect(url_for('auth.login'))
        else:
            flash("Nie ma takiego użytkownika", 'danger')

    return render_template('forgot.html', form=form)


@auth_bp.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        username = s.loads(token, salt='reset-password', max_age=3600)
    except:
        flash('Niepoprawny lub wygasły token.', 'danger')
        return redirect(url_for('auth.login'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user:
            salt = secrets.token_hex(16)
            hashed_password = generate_password_hash(salt + password)
            user.password_hash = hashed_password
            user.password_salt = salt
            db.session.commit()
            flash("Hasło zostało zresetowane", 'success')
            return redirect(url_for('auth.login'))
        else:
            flash("Niepoprawny token", "danger")
            return redirect(url_for('auth.login'))

    return render_template('reset.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('notes.notes'))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        totp_code = form.totp_code.data

        ip_address = request.remote_addr
        failed_attempt = FailedLoginAttempt.query.filter_by(ip_address=ip_address).first()

        sleep(LOGIN_DELAY)

        if not failed_attempt:
            failed_attempt = FailedLoginAttempt(ip_address=ip_address, failed_attempts=0)
            db.session.add(failed_attempt)
            db.session.commit()

        time_since_last_failed = datetime.utcnow() - failed_attempt.last_failed_attempt
        if failed_attempt.failed_attempts >= LOGIN_ATTEMPT_LIMIT and time_since_last_failed < timedelta(minutes=5):
            time_to_wait = (timedelta(minutes=5) - time_since_last_failed).total_seconds()
            flash(f"Too many failed login attempts. Try again in {int(time_to_wait)} seconds.", "danger")
            return render_template('login.html', form=form)

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, user.password_salt + password):

            if user.totp_secret:
                if not totp_code:
                    flash('TOTP code required.', 'danger')
                    return render_template('login.html', form=form)

                totp = pyotp.TOTP(user.totp_secret)
                if not totp.verify(totp_code):
                    flash('Invalid TOTP code.', 'danger')
                    return render_template('login.html', form=form)

            private_key = decrypt_key(user.encrypted_private_key, password, user.key_salt)
            if private_key:
                # Zapisz odszyfrowany klucz prywatny w sesji
                session['private_key'] = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode()
                print(f"Private key stored in session")

            else:
                flash("Nie udało się odszyfrować klucza prywatnego.", "danger")
                return render_template('login.html', form=form)

            login_user(user)

            failed_attempt.failed_attempts = 0
            db.session.commit()

            next_page = request.args.get('next')
            if user.last_login_ip != ip_address and user.last_login_ip is not None:
                send_new_login_email(user, ip_address)
            user.last_login_ip = ip_address
            db.session.commit()
            return redirect(next_page if next_page else url_for('notes.notes'))
        else:
            failed_attempt.failed_attempts += 1
            failed_attempt.last_failed_attempt = datetime.utcnow()
            db.session.commit()

            if failed_attempt.failed_attempts >= LOGIN_ATTEMPT_LIMIT:
                flash("Too many failed attempts. Try again in 5 minutes.", "danger")
            else:
                remaining_attempts = LOGIN_ATTEMPT_LIMIT - failed_attempt.failed_attempts
                flash(f"Login failed. Remaining attempts: {remaining_attempts}", "danger")
            return render_template('login.html', form=form)

    return render_template('login.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        enable_totp = form.enable_totp.data

        salt = secrets.token_hex(16)
        hashed_password = generate_password_hash(salt + password)

        totp_secret = None
        if enable_totp:
            totp_secret = pyotp.random_base32()

        if User.query.filter_by(username=username).first():
            flash('Nazwa użytkownika jest już zajęta.', 'danger')
            return render_template('register.html', form=form)

        public_key, encrypted_private_key, key_salt = generate_keys(password)

        user = User(username=username, password_hash=hashed_password, password_salt=salt, totp_secret=totp_secret,
                    email=email, public_key=public_key, encrypted_private_key=encrypted_private_key, key_salt=key_salt)
        db.session.add(user)
        try:
            db.session.commit()
            flash('Rejestracja przebiegła pomyślnie!', 'success')
            if enable_totp:
                return redirect(url_for('auth.show_qr', username=username))
            return redirect(url_for('auth.login'))
        except IntegrityError:
            db.session.rollback()
            flash('Nazwa użytkownika jest już zajęta.', 'danger')

    return render_template('register.html', form=form)


@auth_bp.route('/show_qr/<username>')
def show_qr(username):
    user = User.query.filter_by(username=username).first()
    if not user or not user.totp_secret:
        flash("Niepoprawny kod", "danger")
        return redirect(url_for('auth.register'))

    totp = pyotp.TOTP(user.totp_secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name="SecureNotes")
    qr = QRCode()
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    filename = f'qr_{user.username}.png'
    filepath = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static', filename)
    img.save(filepath)
    return render_template('qr.html', qr_code=filename)


@auth_bp.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)


@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == "POST":
        if current_user.totp_secret:
            current_user.totp_secret = None
        else:
            totp_secret = pyotp.random_base32()
            current_user.totp_secret = totp_secret

        db.session.commit()
        return redirect(url_for('auth.profile'))
    return render_template("profile.html")