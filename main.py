import os
from functools import wraps

from flask import Flask, render_template, request, flash, abort
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, length

app = Flask(__name__)
Bootstrap(app)

app.config['TESTING'] = False
app.config['SECRET_KEY'] = os.getenv("APP_SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///bob.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


class Bob(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)

    def __repr__(self):
        return f'Bob {self.email}'


# with app.app_context():
#     db.create_all()
#
# with app.app_context():
#     new_user = Bob(email="2@gmail.com", password="098765")
#     db.session.add(new_user)
#     db.session.commit()


class LoginForm(FlaskForm):
    user_email = EmailField(label='Email', validators=[DataRequired()])
    user_pass = PasswordField(label='Password', validators=[DataRequired(), length(min=3)])
    submit = SubmitField(label='Log In')


@login_manager.user_loader
def load_user(user_id):
    return Bob.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@app.route("/logout")
@login_required
@admin_only
def logout():
    logout_user()
    return render_template('Logout.html')


@app.route("/", methods=["GET", "POST"])
#
def home():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        b = Bob.query.filter_by(email=login_form.user_email.data).first()
        if b is not None:
            if check_password_hash(b.password, login_form.user_pass.data):
                login_user(b)
                return render_template('index.html', logged_in=True)
            else:
                flash("Wrong password, try again")
                return render_template('Login.html', form=login_form, logged_in=current_user.is_authenticated)

        else:
            if request.method == 'POST':
                hash_and_salted_password = generateHash(login_form.user_pass.data)

                new_user = Bob()
                new_user.email = login_form.user_email.data
                new_user.password = hash_and_salted_password

                db.session.add(new_user)
                db.session.commit()

                flash('You were not my follower, but now you are automatically registered')
                flash('Login again please')

    return render_template('Login.html', form=login_form, logged_in=current_user.is_authenticated)


def generateHash(user_password):
    return generate_password_hash(
        user_password,
        method='pbkdf2:sha256',
        salt_length=8
    )


if __name__ == '__main__':
    app.run(debug=True)
