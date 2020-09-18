from flask_wtf import FlaskForm
from wtforms import Form, SelectField
from wtforms.fields.html5 import DateField  ,DateTimeLocalField,IntegerField,EmailField,TelField
from  wtforms import PasswordField,StringField,DateField,SubmitField
from wtforms.validators import DataRequired ,Email,Regexp
from wtforms.validators import Required,Length,DataRequired,NumberRange,EqualTo,Regexp
from flask_wtf.file import FileField, FileRequired,FileAllowed


class RegisterForm(FlaskForm):
    """Registration form."""
    name = StringField('First Name', validators=[Required(), Length(1, 64)],render_kw={"placeholder": "First Name"})
    email=EmailField('Email',validators=[DataRequired(),Email(),Length(1, 64),Regexp("(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", message="Email is not correct")], render_kw={"placeholder": "Email"})    
    password = PasswordField('Password', validators=[Required()],render_kw={"placeholder": "Password"})
    password_again = PasswordField('Password Confirm',validators=[Required(), EqualTo('password')],render_kw={"placeholder": "Password Confirm"})
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    """Login form."""
    email=EmailField('Email',validators=[DataRequired(),Length(1, 64),Email()], render_kw={"placeholder": "Email"})
    password = PasswordField('Password', validators=[Required()],render_kw={"placeholder": "Password"})
    token = StringField('Token', validators=[Required(), Length(6, 6)],render_kw={"placeholder": "Tolen"})
    submit = SubmitField('Login')