# import os
from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask_sqlalchemy import SQLAlchemy, sqlalchemy
from wtforms import Form, StringField, SelectField, PasswordField, IntegerField, DateField, SubmitField, validators, TimeField
from passlib.hash import sha256_crypt
from functools import wraps
import datetime
import pytz
from werkzeug.datastructures import MultiDict
import os
from flask_heroku import Heroku
from datetime import time

app = Flask(__name__)
app.secret_key = 'teamc4ever'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#not having this throws weird secret errors
app.config['SESSION_TYPE'] = 'filesystem'

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://localhost/swipe' if 'HEROKU' not in os.environ else os.environ['DATABASE_URL']
heroku = Heroku(app)
db = SQLAlchemy(app)

# Create database model
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(20), unique=False, nullable=False)
    last_name = db.Column(db.String(20), unique=False, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(), unique=False, nullable=False)
    has_swipes = db.Column(db.Boolean, unique=False, nullable=False)
    time_registered = db.Column(db.DateTime, unique=False, nullable=False)
    swipes_donated = db.Column(db.Integer, unique=False, nullable=False)
    swipes_received = db.Column(db.Integer, unique=False, nullable=False)

    def __init__(self, first_name, last_name, email, password, has_swipes, time_registered, swipes_donated, swipes_received):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = password
        self.has_swipes = has_swipes
        self.time_registered = time_registered
        self.swipes_donated = swipes_donated
        self.swipes_received = swipes_received

    def __repr__(self):
        return '<User %r>' % self.email

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Please log in first.', 'danger')
            return redirect(url_for('login'))
    return wrap

# Check if user is feeder
def is_feeder(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session['has_swipes'] == True:
            return f(*args, **kwargs)
        else:
            flash('You are not a feeder.', 'danger')
            return redirect(url_for('eat_explore'))
    return wrap

# Check if user is eater
def is_eater(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session['has_swipes'] == False:
            return f(*args, **kwargs)
        else:
            flash('You are not a eater.', 'danger')
            return redirect(url_for('feed_shareMeal'))
    return wrap


@app.route('/')
def index():
    return render_template('index.html')

class RegisterForm(Form):
    first_name = StringField('First name', [
        validators.DataRequired(),
        validators.Length(min=1, max=20)
    ])
    last_name = StringField('Last name', [
        validators.DataRequired(),
        validators.Length(min=1, max=20)
    ])
    has_swipes = SelectField(
            'Do you have meals to spare?',
            [validators.DataRequired(message='Please enter your meal needs')],
            choices=[('true', 'Have meals to spare'), ('false', 'Need meals to survive')]
        )
    email = StringField('Email', [
        validators.DataRequired(),
        validators.Length(min=6, max=50),
        validators.Email(message = 'Please enter a valid email.')
    ])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)

    if request.method == 'POST' and form.validate():
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        password = sha256_crypt.hash(form.password.data) # encrypt password

        if form.has_swipes.data == 'true':
            has_swipes = True
        else:
            has_swipes = False

        new_user = User(first_name, last_name, email, password, has_swipes, datetime.datetime.today(), 0, 0)

        try:
            # Add new user to db
            db.session.add(new_user)
            db.session.commit()
            # Sucessfully added new user to db, redirect to login
            flash('You are now registered and can log in.', 'success')
            return redirect(url_for('login'))
        except sqlalchemy.exc.IntegrityError as error:
            flash('That email is already registered in the system, please log in.', 'danger')
            return render_template('register.html', form=form)
        # Catch other server exceptions
        except Exception as error:
            print(error)
            flash('Server is busy, please try again later.', 'danger')
            return render_template('register.html', form=form)
    # GET method
    else:
        return render_template('register.html', form=form)

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form fields
        email = request.form['email']
        password_candidate = request.form['password']

        current_user = User.query.filter_by(email=email).first()

        # Check if user with email is found in db
        if current_user != None:
            # Compare passwords to see if they match
            if sha256_crypt.verify(password_candidate, current_user.password):
                # Username and password matched!
                session['logged_in'] = True
                session['id'] = current_user.id
                session['first_name'] = current_user.first_name
                session['last_name'] = current_user.last_name
                session['email'] = current_user.email
                session['has_swipes'] = current_user.has_swipes
                session['swipes_donated'] = current_user.swipes_donated
                session['swipes_received'] = current_user.swipes_received

                flash('You are now logged in.', 'success')
                if session['has_swipes']:
                    return redirect(url_for('feed_shareMeal'))
                else:
                    return redirect(url_for('eat_explore'))
            else:
                # User found but password incorrect
                error = 'Please check your password and try again.'
                return render_template('login.html', error = error)
        else:
            # User not found
            error = 'Unrecognized email, please try again.'
            return render_template('login.html', error = error)
    # GET method
    else:
        return render_template('login.html')


# first and return page for feeder
@app.route('/feed_shareMeal')
@is_feeder
@is_logged_in
def feed_shareMeal():
    feeder_meals = UnclaimedMeals.query.filter_by(user_id=session['id']).all()
    session['feeder_meals'] = []
    for meal in feeder_meals:
        if meal.swipe_confirmed == True:
            # delete brown
            db.session.delete(meal)
            db.session.commit()
        else:
            swipe = {}
            swipe['swipe_claimed'] = meal.swipe_claimed
            swipe['swipe_id'] = meal.swipe_id
            swipe['meal_location'] = meal.meal_location[0].upper() + meal.meal_location[1:]
            swipe['time_end'] = meal.time_end
            swipe['intro_message'] = meal.intro_message
            # swipe['swipe_confirmed'] = meal.swipe_confirmed
            swipe['eater_id'] = meal.eater_id
            swipe['first_name'] = User.query.filter_by(id=meal.user_id).first().first_name

            session['feeder_meals'].append(swipe)
    return render_template('feed_shareMeal.html')



# Create database of unclaimed meals, must delete meals once claimed or time runs out
class UnclaimedMeals(db.Model):
    __tablename__ = "unclaimed_meals"
    swipe_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, unique=False, nullable=False)
    meal_location = db.Column(db.String(), unique=False, nullable=False)
    swipe_claimed = db.Column(db.Boolean, unique=False, nullable=False)
    time_begin = db.Column(db.Time, unique=False, nullable=False)
    # time_end = db.Column(db.DateTime, unique=False, nullable=False)
    time_end = db.Column(db.Float, unique=False, nullable=False)
    intro_message= db.Column(db.String(), unique=False, nullable=False)
    swipe_confirmed = db.Column(db.Boolean, unique=False, nullable=False)
    eater_id = db.Column(db.Integer, unique=False, nullable=False)

    def __init__(self, user_id, meal_location, swipe_claimed, time_begin, time_end, intro_message, swipe_confirmed, eater_id):
        self.user_id = user_id
        self.meal_location = meal_location
        self.swipe_claimed = swipe_claimed
        self.time_begin = time_begin
        self.time_end = time_end
        self.intro_message = intro_message
        self.swipe_confirmed = swipe_confirmed
        self.eater_id = eater_id

# Form to share a meal, has the details of unclaimed meals
class ShareMealForm(Form):
    meal_location = SelectField(
            'Location:',
            [validators.DataRequired(message='Please enter your location')],
            choices=[('andrews', 'Andrews Commons'), ('vdub', 'V-Dub'), ('ratty', 'Ratty'), ("jos","Jo's"), ('blueroom', 'Blue Room'), ('ivyroom', 'Ivy Room')]
        )
    # time_begin = DateField('From: ', [
    #     validators.DataRequired(message = 'Please use the correct format: YYYY-MM-DD (Ex: 2019-03-14)')
    # ], format = '%m/%d/%Y %H:%M %p')
    # time_begin = DateField('From: ', [
    #     validators.DataRequired(message = 'Please use the correct format --> MM-DD-YYYY hour:minutes am/pm  (Ex: 10-08-2019 10:30 am)')
    # ], format = '%m-%d-%Y %H:%M %p')
    time_begin = TimeField('From What Time: ', [
        validators.DataRequired(message = 'Please use the correct format --> hour:minutes (Ex: 10:30)')
    ], format = '%H:%M')
    time_end = SelectField('For How Long: ', [
        validators.DataRequired('Please enter how long you will stay here for')
    ], choices=[('.25','15 minutes'), ('.5', '30 minutes'), ('.75', '45 minutes'), ('1', '1 hour'), ('1.25', '1 hour 15 minutes'), ('1.5', '1 hour 30 minutes'), ('1.75', '1 hour 45 minutes'), ('2', '2 hours')]
    )

    intro_message = StringField('Introductory Message:', [
        validators.DataRequired(message='Please enter a message to introduce yourself')
    ])

# Share a meal
@app.route('/feed_details', methods=['GET', 'POST'])
@is_logged_in
@is_feeder
def feed_details():
    form = ShareMealForm(request.form)
    if request.method == 'POST' and form.validate():
        meal_location = form.meal_location.data
        time_begin = form.time_begin.data
        time_end = float(form.time_end.data)
        intro_message = form.intro_message.data
        swipe_claimed = False
        # swipe_claimed = True
        user_id = session['id']

        swipe_confirmed = False
        eater_id = 0
        new_swipe = UnclaimedMeals(user_id, meal_location, swipe_claimed, time_begin, time_end, intro_message, swipe_confirmed, eater_id)

        # try:
            # Add new user to db
        db.session.add(new_swipe)
        db.session.commit()
        # Sucessfully added new user to db, redirect to login
        flash('You have successfully submitted a swipe!', 'success')
        return redirect(url_for('feed_shareMeal'))
        # Catch other server exceptions
        # except Exception as error:
        #     flash('Server is busy, please try again later.', 'danger')
        #     return render_template('feed_details.html', form=form)
    # GET method
    else:
        return render_template('feed_details.html', form=form)

# first page for receiver
@app.route('/eat_explore')
@is_logged_in
@is_eater
def eat_explore():
    eateries = ['andrews', 'jos', 'blueroom', 'ivyroom', 'vdub', 'ratty']

    session['curr_meal'] = []

    for eatery in eateries:
        session[eatery] = []
        count = 0
        meals_available = UnclaimedMeals.query.filter_by(swipe_confirmed=False, meal_location=eatery.strip()).all()

        for meal in meals_available:
            swipe = {}
            swipe['swipe_id'] = meal.swipe_id
            swipe['first_name'] = User.query.filter_by(id=meal.user_id).first().first_name
            swipe['meal_location'] = meal.meal_location
            swipe['time_end'] = meal.time_end

            print('swipes', swipe)

            if meal.eater_id == session['id'] and meal.swipe_claimed == True:
                session['curr_meal'].append(swipe)
                continue
            swipe['swipe_claimed'] = meal.swipe_claimed
            # swipe['swipe_id'] = meal.swipe_id
            # swipe['first_name'] = User.query.filter_by(id=meal.user_id).first().first_name
            # swipe['meal_location'] = meal.meal_location
            # swipe['time_end'] = meal.time_end
            swipe['intro_message'] = meal.intro_message
            # swipe['swipe_confirmed'] = meal.swipe_confirmed
            swipe['eater_id'] = meal.eater_id
            if count == 0:
                swipe['first_card'] = True
                count += 1
            else:
                swipe['first_card'] = False
            session[eatery].append(swipe)

        print(meals_available, session[eatery], session['curr_meal'], eateries)

    for meal in session['curr_meal']:
        print("mealAfter: ",meal)
    return render_template('eat_explore.html')

@app.route('/eater_claim', methods=['POST'])
def eater_claim():
    swipe_id = request.form.get('claim')
    curr_meal = UnclaimedMeals.query.filter_by(swipe_id = swipe_id).first()
    curr_meal.swipe_claimed = True
    curr_meal.eater_id = session['id']
    db.session.commit()
    return redirect(url_for('eat_explore'))
    # claimed meal

@app.route('/feeder_confirm', methods=['POST'])
def feeder_confirm():
    swipe_id = request.form.get('confirm')
    curr_meal = UnclaimedMeals.query.filter_by(swipe_id = swipe_id).first()
    curr_meal.swipe_confirmed = True
    db.session.commit()
    return ('', 204)
    # dbsession.delete(curr_meal)
    # session.commit()
    # db.session.commit()

@app.route('/feeder_thanks', methods=['POST'])
def feeder_thanks():
    swipe_id = request.form.get('confirm')
    return redirect(url_for('feed_shareMeal'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.secret_key = 'teamc4ever'
    app.run(debug=True)