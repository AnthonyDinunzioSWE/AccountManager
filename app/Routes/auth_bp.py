from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from ..Models.user import User
from ..Models.saved_password import SavedPassword
from ..Instances.instances import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash


auth_bp = Blueprint('auth_bp', __name__, template_folder='..templates/auth', static_folder='static')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('main_bp.index'))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('auth_bp.login'))
    return render_template('auth/login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('auth_bp.register'))
        
        if User.query.filter_by(email=email).first():
            flash("Email already exists", 'danger')
            return redirect(url_for('auth_bp.register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password_hash=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('auth_bp.login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while registering. Please try again.', 'danger')
            return redirect(url_for('auth_bp.register'))
        
    return render_template('auth/register.html')


@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            # Here you would typically send a password reset email
            flash('Password reset link has been sent to your email.', 'success')
            return redirect(url_for('auth_bp.login'))
        else:
            flash('Email not found', 'danger')
            return redirect(url_for('auth_bp.forgot_password'))
    
    return render_template('auth/forgot_password.html')

@auth_bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('auth_bp.change_password'))

        if new_password != confirm_new_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('auth_bp.change_password'))

        hashed_new_password = generate_password_hash(new_password)
        current_user.password_hash = hashed_new_password

        try:
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('main_bp.index'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while changing the password. Please try again.', 'danger')
            return redirect(url_for('auth_bp.change_password'))

    return render_template('auth/change_password.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('auth_bp.login'))

@auth_bp.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = User.query.get(current_user.id)
    if user:
        try:
            db.session.delete(user)
            db.session.commit()
            flash('Account deleted successfully!', 'success')
            return redirect(url_for('auth_bp.register'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while deleting the account. Please try again.', 'danger')
            return redirect(url_for('main_bp.profile'))
    else:
        flash('User not found', 'danger')
        return redirect(url_for('main_bp.profile'))
