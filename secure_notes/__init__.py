import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
from flask_wtf import CSRFProtect
from sqlalchemy import func

load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    password_salt = db.Column(db.String(255), nullable=False)
    totp_secret = db.Column(db.String(255), nullable=True)
    notes = db.relationship('Note', backref='author', lazy=True)

    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(50), nullable=True)

    public_key = db.Column(db.Text, nullable=True)
    encrypted_private_key = db.Column(db.Text, nullable=True)
    key_salt = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f"<User {self.username}>"

    def get_id(self):
        return str(self.id)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

class FailedLoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False, unique=True)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    last_failed_attempt = db.Column(db.DateTime, default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self):
        return f"<FailedLoginAttempt {self.ip_address}: {self.failed_attempts} attempts>"


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=func.now())
    updated_at = db.Column(db.DateTime)
    is_encrypted = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_with = db.relationship('SharedNote', backref='note', lazy=True)
    is_public = db.Column(db.Boolean, default=False)
    signature = db.Column(db.Text, nullable=True)

    def __init__(self, content, is_encrypted, user_id, signature, created_at=None):
        self.content = content
        self.is_encrypted = is_encrypted
        self.user_id = user_id
        self.signature = signature
        if created_at is not None:
            self.created_at = created_at


class SharedNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"<SharedNote note_id:{self.note_id} user_id:{self.user_id}>"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_default_secret_key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    csrf = CSRFProtect(app)

    app.config["CONTENT_SECURITY_POLICY"] = {
        "default-src": "'self'",
        "img-src": "*",
        "script-src": ["'self'"],
        "style-src": ["'self'"]
    }
    app.config['SERVER_NAME'] = "local.securenotes.app"

    @app.after_request
    def remove_server_header(response):
        del response.headers['Server']
        return response

    from .routes import auth, notes, main
    app.register_blueprint(auth.auth_bp)
    app.register_blueprint(notes.notes_bp)
    app.register_blueprint(main.main_bp)

    with app.app_context():
        db.create_all()

    return app