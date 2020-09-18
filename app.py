import os
import base64
from io import BytesIO
from flask import Flask, render_template, redirect, url_for, flash, session, \
    abort,request,current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, Length, EqualTo
import onetimepass
import pyqrcode
from flask_qrcode import QRcode
from flask_mail import Mail
from flask_mail import Message
from flask_login import login_user, logout_user, login_required,login_manager
from forms import RegisterForm,LoginForm
from sqlalchemy import create_engine
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from threading import Thread
import socket
import onetimepass
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager 
from flask_bootstrap import Bootstrap
from flask_login import UserMixin
from flask_otp import OTP




app = Flask(__name__)
app.config.from_object('config')
mail = Mail()
mail.init_app(app)
otp = OTP()
otp.init_app(app)
engine = create_engine("mysql+pymysql://root:Sa0366590!@localhost:3306/demo")
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
QRcode(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


class User(UserMixin, db.Model):
    """User model."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(64), index=True)
    name = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo' \
            .format(self.name, self.otp_secret)



# @app.route('/confirm/<token>,<email>')
# def confirm(token,email):
#     current_user=User.query.filter(User.email  ==  email).first()
#     if current_user.confirmed:
#         return redirect(url_for('index'))
#     if current_user.confirm(token):
#         db.session.commit()
#         flash('You have confirmed your account. Thanks!')
#     else:
#         flash('The confirmation link is invalid or has expired.')
#     return redirect(url_for('index'))


@login_manager.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/profile')
def profile():
    return render_template('profile.html')



@app.route('/login')
def login():
    return render_template('login.html',form = LoginForm())

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # # if user is None or not user.verify_password(form.password.data) :
        # # # or not user.verify_totp(form.token.data):
        # #     flash('Invalid username, password or token.')
        # #     return redirect(url_for('login'))
        # if not user or not check_password_hash(user.password, password): 
        #     flash('Please check your login details and try again.')
        #     return redirect(url_for('login'),form = form)
        if user is None or not user.verify_password(form.password.data) or \
                not user.verify_totp(form.token.data):
            flash('Invalid username, password or token.')
            return redirect(url_for('login'))
# if user doesn't exist or password is wrong, reload the page

        # log user in
        session['email']=user.email
        session['name']=user.name
        session['id']=user.id

        email=user.email
        name=user.name
        login_user(user, remember=remember)
        flash('You are already logged in',category='warning')
        return redirect(url_for('profile'))
    return render_template('login.html', form=form)
    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    # if not user or not check_password_hash(user.password, password): 
    #     flash('Please check your login details and try again.')
    #     return redirect(url_for('login')) # if user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    # login_user(user, remember=remember)
    # return redirect(url_for('profile'))

@app.route('/signup')
def signup():
    return render_template('signup.html',form = RegisterForm())

@app.route('/signup', methods=['POST'])
def signup_post():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first() # if this returns a user, then the email already exists in database
        if user: # if a user is found, we want to redirect back to signup page so user can try again  
            flash('Email address already exists')
            return redirect(url_for('signup'))
        user = User(name=form.name.data, password=form.password.data,email=form.email.data)
        db.session.add(user)
        db.session.commit()
        # redirect to the two-factor auth page, passing username in session
        session['email'] = user.email
        return redirect(url_for('two_factor_setup'))
        # create new user with the form data. Hash the password so plaintext version isn't saved.

    return redirect(url_for('signup'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))



@app.route('/twofactor')
def two_factor_setup():
    if 'email' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(email=session['email']).first()
    if user is None:
        return redirect(url_for('index'))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/qrcode')
def qrcode():
    if 'email' not in session:
        abort(404)
    user = User.query.filter_by(email=session['email']).first()
    if user is None:
        abort(404)

    # for added security, remove username from session
    del session['email']

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_totp_uri())
    print("1")
    stream = BytesIO()
    url.svg(stream, scale=3)
    print("2")
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     """User login route."""
#     if current_user.is_authenticated:
#         # if user is logged in we get out of here
#         return redirect(url_for('index'))
#     form = LoginForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=form.email.data).first()
#         if user is None or not user.verify_password(form.password.data) :
#         # or not user.verify_totp(form.token.data):
#             flash('Invalid username, password or token.')
#             return redirect(url_for('login'))

#         # log user in
#         session['email']=user.email
#         session['name']=user.name
#         session['lname'] = user.lname
#         session['id']=user.id
#         session['confirm']=user.confirmed

#         email=user.email
#         name=user.name
#         flash('You are already logged in',category='warning')
#         return redirect(url_for('userIndex'))
#     return render_template('login.html', form=form)



# @app.route('/logout/', methods=['GET'])
# def logout():
#     name=session.get('name')
#     print(session.get('id'))
#     session.clear()
#     flash(f'You successfuly logged out',category='warning')
#     return redirect(url_for('index'))



# create database tables if they don't exist yet


db.create_all()
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)