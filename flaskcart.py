from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate as migrate
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, TextAreaField, IntegerField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import UserMixin, LoginManager, login_required, logout_user, current_user, login_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)

"""
Below are the configurations involved with the flask-application:
   * A secret key for the application's security.
   * Database configuration and mapping.
   * An SqlAlchemy class instance.
   * Migration command. 
"""

app.config['SECRET_KEY'] = 'dev'

# the database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# the SQLAlchemy beneath will be used for all database commands
db = SQLAlchemy(app)

# database migrations
db_migrate = migrate(app, db)

"""
Database Models:

   * Each table in the database needs a class to be created for it.
   * db.Model is required - don't change it.
   * Identify all columns by name and data type.
"""

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date)
    item = db.Column(db.String(23))
    image_file = db.Column(db.String(100))
    description = db.Column(db.String(500))
    contact = db.Column(db.Integer)
    category = db.Column(db.String(100))
    price = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.item}', '{self.date}')"


# forms

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class PostForm(FlaskForm):
    name_of_item = StringField('Item', validators=[DataRequired()])  # name of item
    image_of_item = FileField('Image', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    category_of_item = StringField('Category', validators=[DataRequired()])
    price_of_item = IntegerField('Price', validators=[DataRequired()])
    submit = SubmitField('Okay', validators=[DataRequired()])


# routes

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Sign Up!', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Enter', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/account")
@login_required
def account():
    return render_template('account.html', title='Profile')

@app.route("/")
def index():
    posts = Post.query.all()

    return render_template('index.html', title='Everything', posts=posts)


@app.route("/Add")
@login_required
def add():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(item=form.name_of_item.data, image=form.image_of_item, poster=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('index'))
    return render_template('add_thing.html', title='Add', form=form)




if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
