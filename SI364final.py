########################
######## Set-up ########
########################

#Set-up code until Models section taken from HW4
import os
import requests
import json
import random
from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.debug = True
app.use_reloader = True
app.config['SECRET_KEY'] = 'hardtoguessstring'
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DATABASE_URL') or "postgresql:///SI364finaljakedeg"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

########################
######## Models ########
########################

collections = db.Table('collections',db.Column('party_id',db.Integer, db.ForeignKey('parties.id')),db.Column('pokemon_id',db.Integer, db.ForeignKey('pokemon.id')))
collections2 = db.Table('collections2',db.Column('pokemon_id',db.Integer, db.ForeignKey('pokemon.id')),db.Column('moves_id',db.Integer, db.ForeignKey('moves.id')))

#Taken from HW4 (except for parties variable)
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    parties = db.relationship('Party',backref='users')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

#Taken from HW4
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Pokemon(db.Model):
    __tablename__ = 'pokemon'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    nickname = db.Column(db.String(64))
    idNumber = db.Column(db.Integer)
    partyID = db.relationship('Party',secondary=collections,backref=db.backref('pokemon',lazy='dynamic'),lazy='dynamic')
    ability = db.Column(db.String(64))
    moves1 = db.relationship('Move',secondary=collections2,backref=db.backref('pokemon',lazy='dynamic'),lazy='dynamic')

class Party(db.Model):
    __tablename__ = 'parties'
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(64))
    userID = db.Column(db.Integer, db.ForeignKey('users.id'))
    pkmn = db.relationship('Pokemon',secondary=collections,backref=db.backref('parties',lazy='dynamic'),lazy='dynamic')

class Move(db.Model):
    __tablename__ = 'moves'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    damage = db.Column(db.Integer)
    pp = db.Column(db.Integer)
    moveType = db.Column(db.String(64))
    damageClass = db.Column(db.String(64))
    pkmn = db.relationship('Pokemon',secondary=collections2,backref=db.backref('moves',lazy='dynamic'),lazy='dynamic')

########################
######## Forms #########
########################

#Taken from HW4
class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
    username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password:",validators=[Required()])
    submit = SubmitField('Register User')

    #Additional checking methods for the form
    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')

#Taken from HW4
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class PartyForm(FlaskForm):
    party = StringField('What is the name of the party you would like to create/access?', validators=[Required()])
    submit = SubmitField('Submit')

class UpdateTeam(FlaskForm):
    name = StringField('What pokemon would you like to add to this team?', validators=[Required()])
    nickname = StringField('What would you like to nickname this pokemon?')
    update = SubmitField('Update')

class Update(FlaskForm):
    update = SubmitField('Update')

class Delete(FlaskForm):
    delete = SubmitField('Delete')

########################
### Helper functions ###
########################

def get_or_create_move(move, poke):
    mv = Move.query.filter_by(name=move).first()
    if mv:
        return mv
    else:
        payload = ""
        search = "https://pokeapi.co/api/v2/move/" + move.lower() + "/"
        response = requests.request("GET", search, data=payload)
        data = json.loads(response.text)
        dmg = data["power"]
        pp = data["pp"]
        type1 = data["type"]["name"]
        class1 = data["damage_class"]["name"]
        mv = Move(name=move, damage=dmg, pp=pp, moveType=type1, damageClass=class1)
        db.session.add(mv)
        db.session.commit()
        return mv

#Other helper, only wanted to create pokemon while accessing API so that each is unique
def create_pokemon(pkmn, nick, pt):
    party = Party.query.filter_by(id=pt).first()
    payload = ""
    search = "https://pokeapi.co/api/v2/pokemon/" + pkmn.lower() + "/"
    response = requests.request("GET", search, data=payload)
    data = json.loads(response.text)
    if 'id' in data.keys():
        if len(party.pkmn.all()) < 6:
            pkmnID = int(data["id"])
            abilities = data["abilities"]
            x = random.randint(0, len(abilities)-1)
            ability = abilities[x]["ability"]["name"]
            if not nick:
                nick = pkmn.lower()
            pokemon = Pokemon(name=pkmn.lower(), nickname=nick, idNumber=pkmnID, ability=ability)
            pokemon.partyID.append(party)
            moves = data["moves"]
            y = random.sample(range(0, len(moves)-1), 4)
            for val in y:
                mv = get_or_create_move(move=moves[val]["move"]["name"], poke=pokemon.id)
                pokemon.moves.append(mv)
            party.pkmn.append(pokemon)
            db.session.add(pokemon)
            db.session.commit()
        else:
            flash("Team already has 6 Pokemon!")
    else:
        flash("Pokemon not found in database")

def get_or_create_party(party, current_user):
    user = User.query.filter_by(username=current_user).first()
    pt = Party.query.filter_by(name=party, userID=user.id).first()
    if pt:
        return pt
    else:
        pt = Party(name=party, userID=user.id)
        print(pt.name)
        db.session.add(pt)
        db.session.commit()
        return pt

########################
#### View functions ####
########################

#Routes for error handling
#Handles error for 404 error
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

#Handles error for 500 error
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

#Routes for login, taken from HW4
#Renders form and allows user to login
@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html',form=form)

#Renders form and allows user to logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

#Renders form and allows user to register
@app.route('/register',methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,username=form.username.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

#Used when a user who is not logged in tries accessing a page that can only be used by logged in users
@app.route('/secret')
@login_required
def secret():
    return "You must be logged in to see this page!"

#Other routes
#Renders form to allow creation of new party, uses get_or_creat_party helper function to do this, returns to this page
@app.route('/', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated:
        form = PartyForm()
        if request.method == 'POST':
            print(form.party.data)
            party = get_or_create_party(party=form.party.data, current_user=current_user.username)
            url = '/upTeam/' + str(party.id)
            return redirect(url)
        return render_template('index.html', form=form)
    else:
        return redirect(url_for('secret'))

#Renders form to allow you to choose which team to add a pokemon to, redirects to /upTeam/<teamNum>
@app.route('/upTeams', methods=['GET', 'POST'])
def upTeams():
    if current_user.is_authenticated:
        form = Update()
        parties = Party.query.filter_by(userID=current_user.id).all()
        return render_template('update.html', form=form, parties=parties)
    else:
        return redirect(url_for('secret'))

#Renders form to allow you to choose which team to delete, redirects to /delTeam/<teamNum>
@app.route('/delTeams', methods=['GET', 'POST'])
def delTeams():
    if current_user.is_authenticated:
        form = Delete()
        parties = Party.query.filter_by(userID=current_user.id).all()
        return render_template('delete.html', form=form, parties=parties)
    else:
        return redirect(url_for('secret'))

#Renders form to allow you to add a pokemon to the team, uses get_or_create_pokemon helper function, returns to /upTeams
@app.route('/upTeam/<teamNum>', methods=['GET', 'POST'])
def update(teamNum):
    if current_user.is_authenticated:
        party = Party.query.filter_by(id=teamNum).first()
        form = UpdateTeam()
        if request.method == 'POST':
            pokemon = create_pokemon(pkmn=form.name.data, nick=form.nickname.data, pt=teamNum)
        return render_template('upTeam.html', form=form, pt=party)
    else:
        return redirect(url_for('secret'))

#Actually deletes specified team, redirects to /delTeams
@app.route('/delTeam/<teamNum>', methods=['GET', 'POST'])
def delete(teamNum):
    if current_user.is_authenticated:
        if request.method == "POST":
            pt = Party.query.filter_by(id=teamNum).first()
            if pt:
                pokemon = pt.pkmn
                flash("Successfully deleted " + pt.name)
                for poke in pokemon:
                    db.session.delete(poke)
                db.session.delete(pt)
                db.session.commit()
        return redirect(url_for('delTeams'))
    else:
        return redirect(url_for('secret'))

#Diplays all moves that have been added so far
@app.route('/allmoves', methods=['GET', 'POST'])
def allmoves():
    moves = Move.query.all()
    return render_template('allmoves.html', moves=moves)

#Diplays all pokemon that have been added along with their abilities and moves
@app.route('/allpkmn', methods=['GET', 'POST'])
def allpkmn():
    pkmn = Pokemon.query.all()
    return render_template('allpkmn.html', pkmn=pkmn)

#Displays all teams that have been created so far
@app.route('/allteams', methods=['GET', 'POST'])
def allteams():
    parties = Party.query.all()
    return render_template('allparties.html', parties=parties)

if __name__ == '__main__':
    db.create_all()
    manager.run()
