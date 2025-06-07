from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectMultipleField
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError
from email_validator import validate_email, EmailNotValidError
import re

class HoneypotField(StringField):
    def validate(self, form, extra_validators=tuple()):
        if self.data:
            raise ValidationError("Honeypot field should be empty.")

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    enable_totp = BooleanField('Enable TOTP')
    submit = SubmitField('Register')


    def validate_email(self, field):
        try:
            email = validate_email(field.data)
            field.data = email.normalized
        except EmailNotValidError as e:
            raise ValidationError(f"Niepoprawny format adresu email: {e}")


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    totp_code = StringField('TOTP Code')
    submit = SubmitField('Login')


class NoteForm(FlaskForm):
    content = TextAreaField('Treść', validators=[DataRequired(), Length(max=10000)])
    is_encrypted = BooleanField('Zaszyfruj notatkę')
    submit = SubmitField('Dodaj Notatkę')


class EditNoteForm(FlaskForm):
    content = TextAreaField('Treść', validators=[DataRequired(), Length(max=10000)])
    is_encrypted = BooleanField('Zaszyfruj notatkę')
    submit = SubmitField('Zapisz zmiany')


class ShareNoteForm(FlaskForm):
    shared_with = SelectMultipleField('Udostępnij', coerce=int, choices=[])
    is_public = BooleanField('Udostępnij publicznie')
    submit = SubmitField('Udostępnij')


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Zresetuj hasło')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8),
                                                     lambda form, field: validate_password_strength(field.data)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Zmień hasło')

class EmptyForm(FlaskForm):
    pass


def validate_password_strength(password):
    if not re.search(r"[^a-zA-Z0-9]", password):
        raise ValidationError('Hasło musi zawierać co najmniej 1 znak specjalny')
    if not re.search(r"\d", password):
        raise ValidationError('Hasło musi zawierać co najmniej 1 cyfrę')
    if not re.search(r"[A-Z]", password):
        raise ValidationError('Hasło musi zawierać co najmniej 1 wielką literę')
    if not re.search(r"[a-z]", password):
        raise ValidationError("Hasło musi zawierać co najmniej 1 małą literę")