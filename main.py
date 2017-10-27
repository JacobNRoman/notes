from flask import Flask, request, redirect, render_template, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib
import random
import string

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://notes:lcproject@localhost:8889/notes'
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)
app.secret_key = 'y33kGcyk&P3B'

class Note(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    deleted = db.Column(db.Boolean)
    pub_date = db.Column(db.DateTime)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    

    def __init__(self, body, owner, pub_date=None):
        self.body = body
        self.deleted = False
        if pub_date is None:
            pub_date = datetime.utcnow()
        self.pub_date = pub_date
        self.owner = owner


class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    name = db.Column(db.String(120))
    username = db.Column(db.String(120), unique=True)
    pw_hash = db.Column(db.String(120))
    notes = db.relationship('Note', backref='owner')

    def __init__(self, email, password):
        self.email = email
        self.pw_hash = make_pw_hash(password)

def make_salt():
    return "".join([random.choice(string.ascii_letters) for x in range(5)])

def make_pw_hash(password, salt=None):
    if not salt:
        salt = make_salt()
    hash = hashlib.sha256(str.encode(password + salt)).hexdigest()
    return '{0},{1}'.format(hash, salt)

def check_pw_hash(password, hash):
    salt = hash.split(',')[1]
    if make_pw_hash(password, salt ) == hash:
        return True
    return False

@app.before_request
def require_login():
    allowed_routes = ['login', 'register']
    if request.endpoint not in allowed_routes and 'email' not in session:
        return redirect('/login')


@app.route('/login', methods=['POST', 'GET'] )
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_pw_hash(password, user.pw_hash):
            session['email'] = email
            #creates the session['email'] object that allows us to have a persistent login
            flash("Logged in")
            return redirect('/')
        else:
            flash('User password incorrect, or user does not exist', 'error')

    return render_template('login.html')

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        #TODO: insert some kind of email validation. Regex?
        password = request.form['password']
        #TODO: Complexity checker?
        verify = request.form['verify']
        # everything below is layers of validation.
        if not email or not password or not verify:
            flash("You must provide a valid email, password, and password verification")
            return redirect("/register")
        if len(email) < 4:
            flash("Username must be longer than three characters")
            return redirect("/register")
        if len(password) < 4:
            flash("Password must be longer than three characters")
            return redirect("/register")
        if password != verify:
            flash("Password and verification fields do not match")
            return redirect('/register')
        existing_user = User.query.filter_by(email=email).first()
        if not existing_user:
            # This only runs if registration is successful
            new_user = User(email, password)
            db.session.add(new_user)
            db.session.commit()
            session['email'] = email
            #TODO - before redirecting home, first get their name and profile details. 
            return redirect('/newaccount')
        else:
            flash("User with this email already exists")
            return redirect('/register')
    return render_template('register.html')

@app.route('/newaccount', methods=['GET', 'POST'])
def newAccount():
    if request.method == 'POST':
        user = User.query.filter_by(email=session['email']).first()
        name = request.form['name']
        username = request.form['username'] 
        #TODO check if username already exists, and if so send an error
        user.name = name
        user.username = username
        db.session.commit()
        # TODO: add birthday
        return redirect("/")
    return render_template("newaccount.html")

@app.route('/logout')
def logout():
    del session['email']
    return redirect('/')

@app.route("/")
def index():
    # This renders the 'Feed' page.
    notes = Note.query.all()
    return render_template('index.html', notes=notes)

@app.route("/profile")
def profile():
    user = User.query.filter_by(email=session['email']).first()
    notes = Note.query.filter_by(owner_id=user.id).all()
    return render_template('profile.html', user=user, notes=notes)
 

@app.route('/newnote', methods=['POST', 'GET'])
def newNote():
    owner = User.query.filter_by(email=session['email']).first()
    if request.method == 'POST':
        # the indented code below handles the submission and creation of a new post
        note = request.form['note']
        if not note:
            #TODO validate so that you get an error message if note is over 140 chars
            flash("You didn't write anything!", "error")
            return redirect ('/newnote')
        new_note = Note(note, owner)
        db.session.add(new_note)
        db.session.commit()
        new_note_id = new_note.id
        note = Note.query.filter_by(id=new_note_id).first()
        user = User.query.filter_by(id=note.owner_id).first()
        # after a new post is submitted the user is redirected to that new post's individual page. 
        return render_template("note.html", note=note, user=user)
    return render_template('newnote.html')


@app.route('/delete', methods=['POST'])
def delete_post():
    # this function handles the deleting of posts that occurs on userblog
    blog_id = int(request.form['blog-id'])
    blog = BlogPost.query.get(blog_id)
    blog.deleted = True
    db.session.add(blog)
    db.session.commit()

    return redirect('/userblog')


if __name__ == '__main__':
    app.run()