from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired
from flask_bcrypt import Bcrypt
import threading
import time
import os

heartbeat_log = 'heartbeat_log.txt'

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

class TriageForm(FlaskForm):
    affected_area = SelectMultipleField('Choose Affected Areas', choices=[
        ('1', 'abdomen'),('2', 'back'),('3', 'chest'),('4', 'ear'),
        ('5', 'head'),('6', 'pelvis'),('7', 'tooth'),('8', 'rectum'),
        ('9', 'skin'),('10', 'leg'),('11', 'arm'),('12', 'feet'),
        ('13', 'knee'),('14', 'elbow'),('15', 'wrist'),('16', 'ankle'),
        ('17', 'throat'),('18', 'neck'),('19','eye'),('20','nose')
    ], coerce=int, validators=[DataRequired()])

    feeling = SelectMultipleField('Choose Feelings', choices=[
        ('1', 'chills'),('2', 'feverish'),('3','numb, tingles, electric tweaks'),('4', 'nauseous'),
        ('5', 'dizzy - about to black out'),('6', 'dizzy - room spinning'),('7', 'light-headed'), ('8', 'dry-mouth'),
        ('9', 'sick - flu'),('10', 'sick - want to vomit'),('11', 'short of breath'),('12', 'sleepy'),
        ('13', 'sweaty'),('14', 'thirsy'),('15', 'tired'),('16', 'weak')
    ], coerce=int, validators=[DataRequired()])

    conditions = SelectMultipleField('Choose Conditions', choices=[
        ('1', 'breathe normally'),('2', 'walk normally'),('3', 'move one side - arm and/or leg'),
        ('4', 'urinate normally'),('5', 'defecate normally'),('6','excrete solid feces'),
        ('7', ' remember normally'),('8', 'write normally'),('9', 'speak normally'),
        ('10', 'hear normally - sounds are too loud'),('11', 'hear normally - loss of hearing'),('12', 'hear normally - ringing/hissing in ear'),
        ('13','see properly - blindness'),('14', 'see properly - blurred vision'),('15', 'see properly - double vision'),
        ('16', 'sleep normally'),('17', 'smell normally'),('18', 'swallow normally'),
        ('19', 'stop scratching'),('20', 'stop sweating'), ('21', 'taste properly')
    ])

    medical_history = TextAreaField('Medical History')
    medication = TextAreaField('Medication')

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

        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login')) # now go to the login page and log in
        
        except Exception as e:
            db.session.rollback() #rollback on transaction error
            flash("An error occurred during registration. Please try again", "danger")
            print(f"Error: {e}") # log error for debugging

    return render_template('register.html', form=form)

@app.route('/emergency_departments', methods=['GET', 'POST'])
@login_required
def emergency_departments():
    ed = EmergencyRoom.query.all()
    return render_template('emergency_departments.html', ed=ed)

@app.route('/triage_form', methods=['GET', 'POST'])
def triage_form():
    form = TriageForm(request.form)
    if form.validate_on_submit():
        selected_options_1 = form.affected_area.data
        selected_options_2 = form.feeling.data
        selected_options_3 = form.conditions.data
        medical_history = form.medical_history.data
        medication = form.medication.data
        return f'''
            Selected Affected Areas: {", ".join(map(str, selected_options_1))}<br>
            Selected Feelings: {", ".join(map(str, selected_options_2))}<br>
            Selected Conditions: {", ".join(map(str, selected_options_3))}<br>
            Medical History: {medical_history}<br>
            Medication: {medication}
        '''
    return render_template('triage_form.html', form=form)

#route for ping/echo
@app.route('/admin/ping', methods=['GET'])
@login_required
def ping():
    return 'echo'

#function to send heartbeat every 60 seconds
def heartbeat():
    while True:
        with open(heartbeat_log, 'a') as log_file:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            log_file.write(f'Heartbeat at {timestamp}\n')
        time.sleep(60)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Update current_occupancy for existing emergency rooms using a for loop
        emergency_rooms = [
            {"name": "General Hospital", "location": "123 Main St", "capacity": 50, "current_occupancy": 10},
            {"name": "City Medical Center", "location": "456 Oak Ave", "capacity": 100, "current_occupancy": 40},
            {"name": "Suburban Health Clinic", "location": "789 Pine Rd", "capacity": 30, "current_occupancy": 31},
        ]

        for room in emergency_rooms:
            er = EmergencyRoom.query.filter_by(name=room["name"]).first()
            if er:
                # Update er's occupancy
                er.current_occupancy = room["current_occupancy"]
            else:
                # If er doesn't exist, add it
                new_er = EmergencyRoom(
                    name=room["name"],
                    location=room["location"],
                    capacity=room["capacity"],
                    current_occupancy=room["current_occupancy"]
                )
                db.session.add(new_er)
            db.session.commit()

    #start heartbeat thread
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        heartbeat_thread = threading.Thread(target = heartbeat)
        heartbeat_thread.daemon = True
        heartbeat_thread.start()

    app.run(debug=True)
