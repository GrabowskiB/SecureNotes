from flask import Blueprint, render_template, redirect, url_for, send_from_directory
from flask_login import current_user

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('notes.notes'))
    return render_template('index.html')

@main_bp.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)