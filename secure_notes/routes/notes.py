from flask import Blueprint, render_template, redirect, url_for, flash, session
from flask_login import login_required, current_user
from ..forms import NoteForm, EditNoteForm, ShareNoteForm
from .. import db, User, Note, SharedNote
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization, kdf
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from datetime import datetime
import markdown
import bleach
import base64
import os

notes_bp = Blueprint('notes', __name__, url_prefix='/notes')

salt = b'your_static_salt'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)

SECRET_KEY = os.getenv('SECRET_KEY', 'your_default_secret_key')
key = base64.urlsafe_b64encode(kdf.derive(SECRET_KEY.encode()))

fernetkey = Fernet(key)

GLOBAL_ENCRYPTION_KEY = os.getenv('GLOBAL_ENCRYPTION_KEY', '16bytesSecretKey').encode()
IV = b'16bytesIV1234567'  # Initialization vector for AES

allowed_tags = [
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'br', 'strong', 'em',
    'a', 'img', 'ul', 'ol', 'li', 'blockquote', 'pre', 'code', 'span', 'div'
]
allowed_attributes = {
    '*': ['id', 'class', 'style'],
    'a': ['href', 'title', 'rel'],
    'img': ['src', 'alt', 'title', 'width', 'height'],
    'span': ['class', 'style'],
    'div': ['class', 'style']
}

def encrypt_content(content):
    cipher = Cipher(algorithms.AES(GLOBAL_ENCRYPTION_KEY), modes.CFB(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(content.encode()) + encryptor.finalize()
    return base64.b64encode(encrypted).decode()

def decrypt_content(encrypted_content):
    cipher = Cipher(algorithms.AES(GLOBAL_ENCRYPTION_KEY), modes.CFB(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(base64.b64decode(encrypted_content)) + decryptor.finalize()
    return decrypted.decode()

def bleach_html(html):
    return bleach.clean(
        html,
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=True
    )

def sign_note_content(private_key, content):
    return private_key.sign(
        content.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_note_signature(public_key, content, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            content.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

@notes_bp.route('/', methods=['GET', 'POST'])
@login_required
def notes():
    form = NoteForm()
    if form.validate_on_submit():
        content = form.content.data
        is_encrypted = form.is_encrypted.data

        private_key_pem = session.get('private_key')
        if not private_key_pem:
            flash("Błąd: brak klucza prywatnego w sesji.", "danger")
            return redirect(url_for('notes.notes'))

        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )

        signature = base64.b64encode(sign_note_content(private_key, content)).decode()

        encrypted_content = encrypt_content(content) if is_encrypted else content

        now = datetime.utcnow()
        note = Note(
            content=encrypted_content,
            is_encrypted=is_encrypted,
            user_id=current_user.id,
            created_at=now,
            signature=signature  # Zapisz podpis
        )

        db.session.add(note)
        db.session.commit()
        flash('Notatka dodana z podpisem!', 'success')
        return redirect(url_for('notes.notes'))

    user_notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.created_at.desc()).all()
    shared_notes = Note.query.join(SharedNote, Note.id == SharedNote.note_id).filter(SharedNote.user_id == current_user.id).order_by(Note.created_at.desc()).all()
    notes = user_notes + shared_notes

    for note in notes:
        author = User.query.get(note.user_id)
        if note.signature and author and author.public_key:
            public_key = serialization.load_pem_public_key(
                author.public_key.encode(),
                backend=default_backend()
            )
            try:
                content_to_verify = decrypt_content(note.content) if note.is_encrypted else note.content
                note.is_signature_valid = verify_note_signature(
                    public_key,
                    content_to_verify,
                    note.signature
                )
                note.content = decrypt_content(note.content) if note.is_encrypted else note.content
            except Exception:
                note.content = "Notatka nie może być wyświetlona ponieważ jest uszkodzona"
                note.is_signature_valid = False
        else:
            note.is_signature_valid = None  # Brak podpisu lub klucza

        note.content = bleach_html(markdown.markdown(note.content,
                       output_format="html5",
                       tab_length=4,
                       extensions=['nl2br', "fenced_code", "tables", "codehilite"],
                       link_patterns=['http://*', 'https://*']))

    return render_template("notes.html", form=form, notes=notes)


@notes_bp.route('/edit/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
    if not note:
        flash("Nie znaleziono notatki", 'danger')
        return redirect(url_for("notes.notes"))

    if note.is_encrypted:
        note.content = decrypt_content(note.content)

    form = EditNoteForm(obj=note)

    if form.validate_on_submit():
        content = form.content.data
        is_encrypted = form.is_encrypted.data

        private_key_pem = session.get('private_key')
        if not private_key_pem:
            flash("Błąd: brak klucza prywatnego w sesji.", "danger")
            return redirect(url_for('notes.notes'))

        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )

        signature = base64.b64encode(sign_note_content(private_key, content)).decode()

        note.content = encrypt_content(content) if is_encrypted else content
        note.is_encrypted = is_encrypted
        note.signature = signature  # Zaktualizuj podpis
        note.updated_at = datetime.utcnow()  # Zaktualizuj datę modyfikacji

        db.session.commit()
        flash("Notatka zmodyfikowana", 'success')
        return redirect(url_for('notes.notes'))

    return render_template("edit_note.html", form=form, note_id=note_id)

@notes_bp.route('/public')
def public_notes():
    notes = Note.query.filter_by(is_public=True).order_by(Note.created_at.desc()).all()
    for note in notes:
        author = User.query.get(note.user_id)
        if note.signature and author and author.public_key:
            public_key = serialization.load_pem_public_key(
                author.public_key.encode(),
                backend=default_backend()
            )
            try:
                content_to_verify = decrypt_content(note.content) if note.is_encrypted else note.content
                note.is_signature_valid = verify_note_signature(
                    public_key,
                    content_to_verify,
                    note.signature
                )
                note.content = decrypt_content(note.content) if note.is_encrypted else note.content
            except Exception:
                note.content = "Notatka nie może być wyświetlona ponieważ jest uszkodzona"
                note.is_signature_valid = False
        else:
            note.is_signature_valid = None  # Brak podpisu lub klucza

        note.content = bleach_html(markdown.markdown(note.content,
                       output_format="html5",
                       tab_length=4,
                       extensions=['nl2br', "fenced_code", "tables", "codehilite"],
                       link_patterns=['http://*', 'https://*']))

    return render_template("public_notes.html", notes=notes)

@notes_bp.route('/share/<int:note_id>', methods=['GET', 'POST'])
@login_required
def share_note(note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
    if not note:
        flash("Nie znaleziono notatki", "danger")
        return redirect(url_for("notes.notes"))

    form = ShareNoteForm()
    form.shared_with.choices = [(u.id, u.username) for u in User.query.filter(User.id != current_user.id).all()]

    if form.validate_on_submit():
        shared_with_users = form.shared_with.data
        is_public = form.is_public.data

        note.is_public = is_public

        for user_id in shared_with_users:
            user = User.query.get(user_id)
            if user:
                shared_note = SharedNote.query.filter_by(note_id=note_id, user_id=user_id).first()
                if not shared_note:
                    shared_note = SharedNote(note_id=note_id, user_id=user_id)
                    db.session.add(shared_note)

        db.session.commit()
        flash("Notatka udostępniona", "success")
        return redirect(url_for("notes.notes"))

    return render_template("share_note.html", form=form, note_id=note.id, note=note)