from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField, SelectField
from sqlalchemy import Integer, String, DateTime
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
    user_type = db.Column(db.String(20), nullable=False)

class EmergencyRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    current_occupancy = db.Column(db.Integer, nullable=False)

class ERAdmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    affected_area = db.Column(db.String, nullable=False)
    feeling = db.Column(db.String, nullable=False)
    conditions = db.Column(db.String, nullable=False)
    medical_history = db.Column(db.String, nullable=True)
    medication = db.Column(db.String, nullable=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())


class PhysicianNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    er_admission_id = db.Column(db.Integer, db.ForeignKey('er_admission.id'), nullable=False)
    physician_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Add this line
    note_text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())


class PhysicianNoteForm(FlaskForm):
    note_text = TextAreaField('Medical Notes', validators=[DataRequired()])
    submit = SubmitField('Add Note')



# makes the input for username and password
class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    
    user_type = SelectField('User Type', choices=[
    ('', 'Select User Type'),  # Placeholder option
    ('nurse', 'Nurse'),
    ('patient', 'Patient'),
    ('admin', 'Admin'),
    ('physician','Physician')
    ], validators=[InputRequired(message="Please select a user type")])

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

class TriageEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Assuming each entry is tied to a user
    affected_area = db.Column(db.String(200), nullable=False)
    feeling = db.Column(db.String(200), nullable=False)
    conditions = db.Column(db.String(200), nullable=False)
    medical_history = db.Column(db.Text, nullable=True)
    medication = db.Column(db.Text, nullable=True)
    status = db.Column(db.Text, default='Waiting for Admission')
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())


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


                if user.user_type == 'patient':
                    return redirect(url_for('dashboard'))
                elif user.user_type == 'nurse':
                    return redirect(url_for('nurse_dashboard'))
                elif user.user_type == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user.user_type == 'physician':
                    return redirect(url_for('physician_dashboard'))
                
            else:
                flash('Invalid password. Please try again.', 'danger') #messaging for invalid password
        else:
            flash('Username does not exist. Please check your username.', 'danger') #messagig for invalid username
            
    return render_template('login.html', form=form) # sent back to login because there were issues

#the page responsible for the dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.user_type == 'patient':
        # Fetch ER admissions for the current patient
        er_admissions = ERAdmission.query.filter_by(user_id=current_user.id).all()
        
        # Fetch notes for these admissions
        patient_notes = {}
        for admission in er_admissions:
            notes = PhysicianNote.query.filter_by(patient_id=current_user.id).all()
            patient_notes[admission.id] = notes
        
        return render_template('dashboard.html', 
                               er_admissions=er_admissions, 
                               patient_notes=patient_notes)
    
    return render_template('dashboard.html')

# Route to handle the admit form request
@app.route('/admit_form/<int:entry_id>', methods=['POST'])
def admit_form(entry_id):
    # Fetch the triage entry from the database
    triage_entry = TriageEntry.query.get(entry_id)

    if triage_entry:
        # Create a new ERAdmission record with the data from the triage entry
        er_admission = ERAdmission(
            user_id=triage_entry.user_id,
            affected_area=triage_entry.affected_area,
            feeling=triage_entry.feeling,
            conditions=triage_entry.conditions,
            medical_history=triage_entry.medical_history,
            medication=triage_entry.medication,
            timestamp=triage_entry.timestamp,
        )
        
        # Add the ER admission to the database
        db.session.add(er_admission)
        #db.session.commit()

       
        triage_entry.status = 'Admitted' 
        db.session.commit()

    # Redirect back to the nurse dashboard
    return redirect(url_for('nurse_dashboard'))

@app.route('/nurse_dashboard', methods=['GET', 'POST'])
@login_required
def nurse_dashboard():
    if current_user.user_type != 'nurse':
        flash("Access restricted to nurses only.", "danger")
        return redirect(url_for('dashboard'))

    triage_entries = TriageEntry.query.filter(TriageEntry.status != 'Admitted').all()

    # Human-readable mappings
    AFFECTED_AREA_MAP = {
    '1': 'abdomen',
    '2': 'back',
    '3': 'chest',
    '4': 'ear',
    '5': 'head',
    '6': 'pelvis',
    '7': 'tooth',
    '8': 'rectum',
    '9': 'skin',
    '10': 'leg',
    '11': 'arm',
    '12': 'feet',
    '13': 'knee',
    '14': 'elbow',
    '15': 'wrist',
    '16': 'ankle',
    '17': 'throat',
    '18': 'neck',
    '19': 'eye',
    '20': 'nose'
}

    FEELING_MAP =  {
    '1': 'chills',
    '2': 'feverish',
    '3': 'numb, tingles, electric tweaks',
    '4': 'nauseous',
    '5': 'dizzy - about to black out',
    '6': 'dizzy - room spinning',
    '7': 'light-headed',
    '8': 'dry-mouth',
    '9': 'sick - flu',
    '10': 'sick - want to vomit',
    '11': 'short of breath',
    '12': 'sleepy',
    '13': 'sweaty',
    '14': 'thirsty',
    '15': 'tired',
    '16': 'weak'
}

    CONDITION_MAP =  {
    '1': 'breathe normally',
    '2': 'walk normally',
    '3': 'move one side - arm and/or leg',
    '4': 'urinate normally',
    '5': 'defecate normally',
    '6': 'excrete solid feces',
    '7': 'remember normally',
    '8': 'write normally',
    '9': 'speak normally',
    '10': 'hear normally - sounds are too loud',
    '11': 'hear normally - loss of hearing',
    '12': 'hear normally - ringing/hissing in ear',
    '13': 'see properly - blindness',
    '14': 'see properly - blurred vision',
    '15': 'see properly - double vision',
    '16': 'sleep normally',
    '17': 'smell normally',
    '18': 'swallow normally',
    '19': 'stop scratching',
    '20': 'stop sweating',
    '21': 'taste properly'
}
    


    # Pass data and mappings to template
    return render_template(
        'nurse_dashboard.html',
        triage_entries=triage_entries,
        affected_area_map=AFFECTED_AREA_MAP,
        feeling_map=FEELING_MAP,
        condition_map=CONDITION_MAP
    )

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if current_user.user_type != 'admin':
        flash("Access restricted to admins only.", "danger")
        return redirect(url_for('dashboard'))
    
    ping_result = None
    heartbeat_result = None

    if request.method == 'POST':
        if 'ping_button' in request.form:
            ping_result = 'echo'

        elif 'heartbeat_button' in request.form:
            if os.path.exists(heartbeat_log):
                with open(heartbeat_log, 'r') as log_file:
                    heartbeat_result = log_file.read()
            else:
                heartbeat_result = 'Heartbeat log not found'

    return render_template('admin_dashboard.html', ping_result = ping_result, heartbeat_result = heartbeat_result)

@app.route('/physician_dashboard', methods=['GET', 'POST'])
@login_required
def physician_dashboard():
    if current_user.user_type != 'physician':
        flash("Access restricted to physicians only.", "danger")
        return redirect(url_for('dashboard'))
    # Human-readable mappings
    AFFECTED_AREA_MAP = {
    '1': 'abdomen',
    '2': 'back',
    '3': 'chest',
    '4': 'ear',
    '5': 'head',
    '6': 'pelvis',
    '7': 'tooth',
    '8': 'rectum',
    '9': 'skin',
    '10': 'leg',
    '11': 'arm',
    '12': 'feet',
    '13': 'knee',
    '14': 'elbow',
    '15': 'wrist',
    '16': 'ankle',
    '17': 'throat',
    '18': 'neck',
    '19': 'eye',
    '20': 'nose'
}

    FEELING_MAP =  {
    '1': 'chills',
    '2': 'feverish',
    '3': 'numb, tingles, electric tweaks',
    '4': 'nauseous',
    '5': 'dizzy - about to black out',
    '6': 'dizzy - room spinning',
    '7': 'light-headed',
    '8': 'dry-mouth',
    '9': 'sick - flu',
    '10': 'sick - want to vomit',
    '11': 'short of breath',
    '12': 'sleepy',
    '13': 'sweaty',
    '14': 'thirsty',
    '15': 'tired',
    '16': 'weak'
}

    CONDITION_MAP =  {
    '1': 'breathe normally',
    '2': 'walk normally',
    '3': 'move one side - arm and/or leg',
    '4': 'urinate normally',
    '5': 'defecate normally',
    '6': 'excrete solid feces',
    '7': 'remember normally',
    '8': 'write normally',
    '9': 'speak normally',
    '10': 'hear normally - sounds are too loud',
    '11': 'hear normally - loss of hearing',
    '12': 'hear normally - ringing/hissing in ear',
    '13': 'see properly - blindness',
    '14': 'see properly - blurred vision',
    '15': 'see properly - double vision',
    '16': 'sleep normally',
    '17': 'smell normally',
    '18': 'swallow normally',
    '19': 'stop scratching',
    '20': 'stop sweating',
    '21': 'taste properly'
}
    # Fetch all ER admissions
    er_admissions = ERAdmission.query.all()
    for admission in er_admissions:
        # Split the comma-separated values
        affected_areas = [AFFECTED_AREA_MAP.get(area.strip(), area) for area in admission.affected_area.split(',')]
        feelings = [FEELING_MAP.get(feeling.strip(), feeling) for feeling in admission.feeling.split(',')]
        conditions = [CONDITION_MAP.get(condition.strip(), condition) for condition in admission.conditions.split(',')]

        # Rejoin the lists into comma-separated strings
        admission.affected_area = ', '.join(affected_areas)
        admission.feeling = ', '.join(feelings)
        admission.conditions = ', '.join(conditions)

    # Fetch notes for each admission
    admission_notes = {}
    for admission in er_admissions:
        notes = PhysicianNote.query.filter_by(er_admission_id=admission.id).all()
        admission_notes[admission.id] = notes

    # Prepare a form for notes
    note_form = PhysicianNoteForm()

    return render_template('physician_dashboard.html', 
                           er_admissions=er_admissions, 
                           admission_notes=admission_notes,
                           note_form=note_form)

@app.route('/add_physician_note/<int:admission_id>', methods=['POST'])
@login_required
def add_physician_note(admission_id):
    if current_user.user_type != 'physician':
        flash("Access restricted to physicians only.", "danger")
        return redirect(url_for('dashboard'))

    form = PhysicianNoteForm()
    if form.validate_on_submit():
        # Find the ER admission to get the patient_id
        er_admission = ERAdmission.query.get(admission_id)
        if er_admission:
            # Create a new physician note
            new_note = PhysicianNote(
                er_admission_id=admission_id,
                physician_id=current_user.id,
                patient_id=er_admission.user_id,  # Add the patient_id
                note_text=form.note_text.data
            )
            db.session.add(new_note)
            db.session.commit()
            

    return redirect(url_for('physician_dashboard'))

@app.route('/remove_patient/<int:admission_id>', methods=['POST'])
@login_required
def remove_patient(admission_id):
    if current_user.user_type != 'physician':
        return redirect(url_for('dashboard'))

    # Find the ER admission
    er_admission = ERAdmission.query.get(admission_id)
    if er_admission:
        # Remove from ER admissions
        db.session.delete(er_admission)
        db.session.commit()
        

    return redirect(url_for('physician_dashboard'))

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
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            user_type=form.user_type.data  # Save the selected user type
        )

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
@login_required
def triage_form():
    form = TriageForm(request.form)
    if form.validate_on_submit():
        
        selected_options_1 = ','.join(map(str, form.affected_area.data))
        selected_options_2 = ','.join(map(str, form.feeling.data))
        selected_options_3 = ','.join(map(str, form.conditions.data))
        """
        selected_options_1 = form.affected_area.data
        selected_options_2 = form.feeling.data
        selected_options_3 = form.conditions.data
        """
        medical_history = form.medical_history.data
        medication = form.medication.data
        
        # Create a new triage entry
        new_entry = TriageEntry(
            user_id=current_user.id,
            affected_area=selected_options_1,
            feeling=selected_options_2,
            conditions=selected_options_3,
            medical_history=medical_history,
            medication=medication,
            status='Waiting for Admission'
        )
        
        try:
            db.session.add(new_entry)
            db.session.commit()
            flash('Triage form submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'danger')
            print(f"Error: {e}")

    return render_template('triage_form.html', form=form)


#route for ping/echo
@app.route('/admin/ping', methods=['GET'])
@login_required
def ping():
    if current_user.user_type != 'admin':
        flash("Access restricted to admins only.", "danger")
        return redirect(url_for('dashboard'))
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
        # Update current_occupancy for existing emergency rooms
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
