from flask import Blueprint, Response, jsonify, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from ..Models.user import User
from ..Models.saved_password import SavedPassword
from ..Instances.instances import db, login_manager
from ..Helpers.timeset_get import timeset_get
from ..Helpers.password_generator import password_generator, hash_password, unhash_password 
import uuid

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

        flash(f'Generated Password: {password}', 'success')
        return render_template('main/password_generator.html', generated_password=password)
    return render_template('main/password_generator.html')
    
@main_bp.route('/delete_password/<uuid:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    if request.method == 'POST':
        password = SavedPassword.query.get_or_404(password_id)
        if password.user_id != current_user.id:
            flash('You do not have permission to delete this password.', 'danger')
            return redirect(url_for('main_bp.profile'))
        
        try:
            db.session.delete(password)
            db.session.commit()
            flash('Password deleted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while deleting the password. Please try again.', 'danger')
        
        return redirect(url_for('main_bp.profile'))
    
@main_bp.route('/hash_password', methods=['POST'])
@login_required
def hash_password_route():
    password = request.form.get('password')
    hashed_password = hash_password(password)
    flash('Password hashed successfully!', 'success')
    return render_template('main/password_generator.html', generated_password=password, hashed_password=hashed_password)

@main_bp.route('/unhash_password', methods=['POST'])
@login_required
def unhash_password_route():
    try:
        # Convert the password_id to a UUID object
        password_id = uuid.UUID(request.form.get('id'))
    except ValueError:
        flash('Invalid password ID.', 'danger')
        return redirect(url_for('main_bp.profile'))

    saved_password = SavedPassword.query.get_or_404(password_id)

    if saved_password.user_id != current_user.id:
        flash('You do not have permission to unhash this password.', 'danger')
        return redirect(url_for('main_bp.profile'))

    if unhash_password(saved_password.hashed_value, saved_password.value):
        saved_password.is_unhashed = not saved_password.is_unhashed  # Toggle the state

    db.session.commit()  # Save the updated state to the database

    saved_passwords = SavedPassword.query.filter_by(user_id=current_user.id).all()
    return render_template(
        'main/profile.html',
        saved_passwords=saved_passwords,
        current_user=current_user,
        timeset=timeset_get()
    )

@main_bp.route('/save_password', methods=['POST'])
@login_required
def save_password():
    if request.method == 'POST':
        password_type = request.form.get('type')
        password_value = request.form.get('value')

        # Hash the password value before saving
        hashed_value = hash_password(password_value)
        print(f'Hashed Value Saved: {hashed_value}')
        

        new_password = SavedPassword(
            type=password_type,
            value=password_value,
            hashed_value=hashed_value,
            user_id=current_user.id
        )

        print(f'Database Stored Value Hash: {new_password.hashed_value}')

        try:
            db.session.add(new_password)
            db.session.commit()
            flash('Password saved successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while saving the password. Please try again.', 'danger')
        
        return redirect(url_for('main_bp.generate_password'))

@main_bp.route('/copy_password', methods=['POST'])
@login_required
def copy_password():
    data = request.get_json()
    password_id = data.get('id')

    try:
        # Convert the password_id to a UUID object
        password_id = uuid.UUID(password_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid password ID.'}), 400

    saved_password = SavedPassword.query.get_or_404(password_id)

    if saved_password.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Permission denied.'}), 403

    # Determine which value was copied based on the `is_unhashed` flag
    value_to_copy = saved_password.value if saved_password.is_unhashed else saved_password.hashed_value

    # Return the flash message in the JSON response
    return jsonify({'success': True, 'message': f'Copied to clipboard: {value_to_copy}'}), 200

@main_bp.route('/export_vault', methods=['GET'])
@login_required
def export_vault():
    passwords = SavedPassword.query.filter_by(user_id=current_user.id).all()
    export_format = request.args.get('format', 'json')

    if export_format == 'csv':
        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Type', 'Value', 'Hashed Value', 'Created At'])
        for password in passwords:
            writer.writerow([password.type, password.value, password.hashed_value, password.created_at])
        output.seek(0)

        return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=vault.csv"})
    else:
        return jsonify([{
            "type": password.type,
            "value": password.value,
            "hashed_value": password.hashed_value,
            "created_at": password.created_at.isoformat()
        } for password in passwords])
    
@main_bp.route('/password_strength')
@login_required
def password_strength():
    return render_template('main/password_stength.html', current_user=current_user)
