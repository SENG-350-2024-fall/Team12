from flask import Flask, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

'''
The following code was modified from:

Neupane, Arpan. "Python Flask Authentication Tutorial." GitHub, 2023, https://github.com/arpanneupane19/Python-Flask-Authentication-Tutorial.

Specifically app set up, login, registeration, home, and user database set up.

'''

# creating teh flask instance - the webapp
app = Flask(__name__)

#creating a SQLite database and pass our app to it
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

#db is the instance of the database, bcrypt hashes the passwords
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


login_manager = LoginManager() # creates a login manager (built in flask module)
login_manager.init_app(app) # links to our flask app
login_manager.login_view = 'login' # where to redirect users if they can't login - so bakc to login page

#this function loads a user from teh database
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) #user class is our database


#creating the User table in our database 
#only stores username and password rn

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class EmergencyRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    current_occupancy = db.Column(db.Integer, nullable=False)


# makes the input for username and password
class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')
    #make sure that the username doesnt already exist
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            flash('Username already exists.', 'danger')
            raise ValidationError(
                'That username already exists. Please choose a different one.')

#the login form also giving an username and passeord box. 
class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login') #built in function from FlaskForm. Login is the nae on the button

#home route so the html page that will render when your at home
@app.route('/')
def home():
    return render_template('home.html')

#making a route for login page 
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm() ## passing in the login form class we made above
    if form.validate_on_submit(): # built in function that makes sure all the input is valid
        user = User.query.filter_by(username=form.username.data).first()
        if user: # if a user exists 
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user) # login user once again is a built in function with flask login
                return redirect(url_for('dashboard')) # everything is correct so go to dashboard
            else:
                flash('Invalid password. Please try again.', 'danger') #messaging for invalid password
        else:
            flash('Username does not exist. Please check your username.', 'danger') #messagig for invalid username
            
    return render_template('login.html', form=form) # sent back to login because there were issues

#the page responsible for the dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

# log out page 
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm() # getting teh reisterForm class from earlier

    if form.validate_on_submit(): # make sure valid data is inputted
        hashed_password = bcrypt.generate_password_hash(form.password.data) # encrypt password
        new_user = User(username=form.username.data, password=hashed_password) # add to database
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login')) # now go to the login page and log in

    return render_template('register.html', form=form)

@app.route('/emergency_departments', methods=['GET', 'POST'])
@login_required
def emergency_departments():
    ed = EmergencyRoom.query.all()
    return render_template('emergency_departments.html', ed=ed)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
                # Hardcode some emergency rooms
        if EmergencyRoom.query.count() == 0:  # To prevent duplicate entries
            er1 = EmergencyRoom(name="General Hospital", location="123 Main St", capacity=50, current_occupancy=10)
            er2 = EmergencyRoom(name="City Medical Center", location="456 Oak Ave", capacity=100, current_occupancy=40)
            er3 = EmergencyRoom(name="Suburban Health Clinic", location="789 Pine Rd", capacity=30, current_occupancy=5)

            db.session.add_all([er1, er2, er3])
            db.session.commit()
    app.run(debug=True)
