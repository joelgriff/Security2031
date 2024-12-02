import base64
import io
import pyotp
import qrcode
from flask import Blueprint, render_template, flash, redirect, url_for, session
from accounts.forms import RegistrationForm, MFASetupForm
from config import User, db, limiter, Post
from flask_login import login_user, login_required, current_user, logout_user
from accounts.forms import LoginForm
from config import User
from werkzeug.security import check_password_hash

from posts.views import posts

accounts_bp = Blueprint('accounts', __name__, template_folder='templates')

@accounts_bp.route('/registration', methods=['GET', 'POST'])
@accounts_bp.route('/registration', methods=['GET', 'POST'])
def registration():
    if current_user.is_authenticated:  # Check if the user is already logged in
        flash("You are already logged in. Registration is not allowed.", "danger")
        return redirect(url_for('posts.posts'))

    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', category="danger")
            return render_template('accounts/registration.html', form=form)

        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data)

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        flash('Please setup MFA.')
        return redirect(url_for('accounts.setup_mfa'))

    return render_template('accounts/registration.html', form=form)


@accounts_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@limiter.limit("500 per day")
def login():
    form = LoginForm()

    if session.get('invalid_attempts',0) >= 3:
        if form.validate_on_submit():
            return redirect(url_for('login'))
        return render_template('accounts/login.html', form=None, locked=True)



    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and user.verify_password(form.password.data) and user.verifyPin(form.pin.data):

            session['invalid_attempts'] = 0
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('posts.posts'))
        else:
            invalid_attempts = session.get('invalid_attempts', 0) + 1
            session['invalid_attempts'] = invalid_attempts
            remaining_attempts = 3 - invalid_attempts
            flash(f'Invalid credentials. {remaining_attempts} attempts remaining.', 'danger')





    return render_template('accounts/login.html', form=form)

@accounts_bp.route('/account')
@login_required
def account():
    if not current_user.is_authenticated:
        flash("Please log in to access your account", category="danger")
        return redirect(url_for('accounts.login'))

    user_posts = Post.query.filter_by(userid=current_user.id).all()
    return render_template('accounts/account.html', user=current_user, posts=user_posts)

@accounts_bp.route('/unlock', methods=['GET'])
def unlock_user():
    session['invalid_attempts'] = 0
    flash('Your account has been unlocked. You can now try logging in again.', 'success')
    return redirect(url_for('login'))


@accounts_bp.route('/setup-mfa', methods=['GET', 'POST'])
@login_required
def setup_mfa():

    if not current_user.mfa_key or not current_user.otp_uri:
        current_user.mfa_key = pyotp.random_base32()
        current_user.otp_uri = pyotp.TOTP(current_user.mfa_key).provisioning_uri(
            name=current_user.email,
            issuer_name="YourAppName"
        )
        db.session.commit()

    qr = qrcode.make(current_user.otp_uri)
    qr_stream = io.BytesIO()
    qr.save(qr_stream, format="PNG")
    qr_stream.seek(0)
    qr_png = base64.b64encode(qr_stream.getvalue()).decode('utf-8')

    print("QR -->" + current_user.otp_uri)
    print("key --> " + current_user.mfa_key)

    if not current_user.otp_uri:
        current_user.otp_uri = qr_png
        db.session.commit()

    form = MFASetupForm()

    if form.validate_on_submit():
        totp = pyotp.TOTP(current_user.mfa_key)
        if totp.verify(form.verification_code.data):
            current_user.mfa_enabled = True
            db.session.commit()
            flash("MFA setup complete! You can now use MFA to log in.", "success")
            return redirect(url_for('posts.posts'))
        else:
            flash("Invalid verification code. Please try again.", "danger")

    return render_template('mfa_setup.html', form=form, secret_key=current_user.mfa_key, qr_png=qr_png)

@accounts_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('accounts.login'))

@accounts_bp.route('/protect')
@login_required
def protect():
    return "Protected Page"