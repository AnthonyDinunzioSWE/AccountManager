from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from ..Models.user import User
from ..Models.saved_password import SavedPassword
from ..Instances.instances import db, login_manager
from ..Helpers.timeset_get import timeset_get
from ..Helpers.password_generator import password_generator, hash_password, unhash_password 


main_bp = Blueprint('main_bp', __name__, template_folder='..templates/main', static_folder='static')


@main_bp.route('/')
def index():
    return render_template('main/index.html', current_user=current_user)


@main_bp.route('/profile')
@login_required
def profile():
    saved_passwords = SavedPassword.query.filter_by(user_id=current_user.id).all()
    return render_template('main/profile.html', saved_passwords=saved_passwords, current_user=current_user, timeset=timeset_get())

@main_bp.route('/update_profile', methods=['POST'])
def update_profile():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('main_bp.profile'))
        
        user = User.query.get(current_user.id)
        user.email = email
        user.password_hash = generate_password_hash(password)

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating the profile. Please try again.', 'danger')
        
        return redirect(url_for('main_bp.profile'))

@main_bp.route('/generate_password', methods=['GET', 'POST'])
@login_required
def generate_password():
    if request.method == 'POST':
        length = int(request.form.get('length', 12))
        char_set = request.form.get('char_set', 'all')
        if char_set == 'letters':
            char_set = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        elif char_set == 'digits':
            char_set = '0123456789'
        elif char_set == 'special':
            char_set = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        else:
            char_set = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        exclude_similar = request.form.get('exclude_similar', 'off') == 'on'
        if exclude_similar == "on":
            exclude_similar = True
        else:
            exclude_similar = False
        
        password = password_generator(length, char_set, exclude_similar)

        password = password_generator(length)
        flash(f'Generated Password: {password}', 'success')
        return redirect(url_for('main_bp.dashboard'))
    return render_template('generate_password.html')


@main_bp.route('/save_password', methods=['POST'])
@login_required
def save_password():
    if request.method == 'POST':
        password_type = request.form.get('type')
        password_value = request.form.get('value')

        new_password = SavedPassword(type=password_type, value=password_value, user_id=current_user.id)

        try:
            db.session.add(new_password)
            db.session.commit()
            flash('Password saved successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while saving the password. Please try again.', 'danger')
        
        return redirect(url_for('main_bp.dashboard'))
    

@main_bp.route('/delete_password/<uuid:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    if request.method == 'POST':
        password = SavedPassword.query.get_or_404(password_id)
        if password.user_id != current_user.id:
            flash('You do not have permission to delete this password.', 'danger')
            return redirect(url_for('main_bp.dashboard'))
        
        try:
            db.session.delete(password)
            db.session.commit()
            flash('Password deleted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while deleting the password. Please try again.', 'danger')
        
        return redirect(url_for('main_bp.dashboard'))
    
@main_bp.route('/hash_password', methods=['POST'])
@login_required
def hash_password_route():
    if request.method == 'POST':
        password = request.form.get('password')
        hashed_password = hash_password(password)
        flash(f'Hashed Password: {hashed_password}', 'success')
        return redirect(url_for('main_bp.dashboard'))
    return render_template('hash_password.html')


@main_bp.route('/unhash_password/<uuid:saved_password_id>', methods=['POST'])
@login_required
def unhash_password_route(saved_password_id):
    if request.method == 'POST':
        saved_password_obj = SavedPassword.query.get_or_404(saved_password_id)
        hashed_password = saved_password_obj.hashed_value
        password = saved_password_obj.value
        is_match = unhash_password(hashed_password, password)
        if is_match:
            flash('Password matches the hashed password.', 'success')
        else:
            flash('Password does not match the hashed password.', 'danger')
        return redirect(url_for('main_bp.dashboard'))
    return render_template('unhash_password.html')