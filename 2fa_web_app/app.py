from flask import Flask

from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from config import Config


app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
migrate = Migrate(app, db)

from models import User

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
from forms import RegistrationForm, LoginForm, OTPForm
from flask import render_template, redirect, url_for, flash, request, session
import pyotp

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check for existing username or email
        # Check for existing username
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists. Please choose another.', 'danger')
            return render_template('register.html', form=form)
        # Check for existing email
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists. Please choose another.', 'danger')
            return render_template('register.html', form=form)
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        secret = pyotp.random_base32()
        user = User(username=form.username.data, email=form.email.data, password=hashed_pw, otp_secret=secret)
        db.session.add(user)
        try:
            db.session.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed due to a database error. Please try a different username/email.', 'danger')
            return render_template('register.html', form=form)
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['pre_2fa_user_id'] = user.id
            totp = pyotp.TOTP(user.otp_secret)
            otp = totp.now()
            from flask_mail import Message
            msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
            msg.body = f'Your OTP is: {otp}'
            mail.send(msg)
            return redirect(url_for('otp'))
        else:
            flash('Login failed. Check email and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    form = OTPForm()
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(form.otp.data):
            session['user_id'] = user.id
            session.pop('pre_2fa_user_id', None)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP. Try again.', 'danger')
    return render_template('otp.html', form=form)

@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
