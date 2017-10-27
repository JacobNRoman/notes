from flask import Flask, request, redirect, render_template, session, flash, g, url_for
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

#followers is an association table that sets up a self-referential many-to-many relationship in the Users table, allowing us to track what Users a given user is following and who follows a given User. 
followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

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
    about_me = db.Column(db.String(140))
    notes = db.relationship('Note', backref='owner')
    followed = db.relationship('User',
        #'User' arg above defines what the right-side table is. Here it is still User. 
        secondary=followers,
        #secondary defines what association table to use, in this case followers
        primaryjoin=(followers.c.follower_id == id),
        #primary join determines what condition links the left side table
        secondaryjoin=(followers.c.followed_id == id),
        #secondary join determines what condition links the right side table
        backref=db.backref('followers', lazy='dynamic'),
        #the backref here defines how the relationship is accessed when coming from the right side, which would give as a list of a Users followers. 
        lazy='dynamic')

    def __init__(self, email, password):
        self.email = email
        self.pw_hash = make_pw_hash(password)
    
    #follow and unfollow methods are written below. We include them here to keep them separate from our view functions, in keeping with MVC. They return an object when they succeed and None when they fail. Keep in mind that even when they return an object, that object msut still be added to the database session and committed. 
    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)
            return self
    
    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)
            return self
    
    #is_following takes a user as an argument, and the runs a query of all users you have followed, filtered by the id of the specific user. Any return is a success, None is a failure. 
    def is_following(self, user):
        return self.followed.filter(followers.c.followed_id == user.id).count()

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

@app.before_request
# load_user gives a persistent global variable containing the current user whenever they are logged in. It requires the g module from flask, which I need to research more carefully. Also, doing it this way isn't terribly secure, as you are constantly passing the user's email through the session. Flask-Login apparently contains a more secure approach. 
def load_user():
    if session['email']:
        user = User.query.filter_by(email=session['email']).first()
    else:
        user = {"name":"Guest"}
    g.user = user


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
        about_me = request.form['aboutme']
        #TODO check if username already exists, and if so send an error
        user.name = name
        user.username = username
        user.about_me = about_me
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

@app.route("/users")
def users():
    # Users simply renders a list of all users. TODO - replace this with a better user browsing and searching solution
    users = User.query.all()
    return render_template("users.html", users=users)


@app.route("/profile/<username>")
def profile(username):
    user = User.query.filter_by(username=username).first()
    notes = Note.query.filter_by(owner_id=user.id).all()
    return render_template('profile.html', user=user, notes=notes)
 
 
@app.route('/newnote', methods=['POST', 'GET'])
def newNote():
    current_user = User.query.filter_by(email=session['email']).first()
    if request.method == 'POST':
        # the indented code below handles the submission and creation of a new post
        note = request.form['note']
        if not note:
            #TODO validate so that you get an error message if note is over 140 chars
            flash("You didn't write anything!", "error")
            return redirect ('/newnote')
        new_note = Note(note, current_user)
        db.session.add(new_note)
        db.session.commit()
        new_note_id = new_note.id
        note = Note.query.filter_by(id=new_note_id).first()
        # after a new post is submitted the user is redirected to that new post's individual page. 
        return render_template("note.html", note=note, current_user=current_user)
    return render_template('newnote.html', current_user=current_user)

@app.route('/follow/<username>')
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {0} not found.'.format(username))
        return redirect('/')
    if user == g.user:
        flash("You can't follow yourself!")
        return redirect(url_for('profile', username=username))
    u = g.user.follow(user)
    if u is None:
        flash('Cannot follow ' + username)
        return redirect(url_for('profile', username=username))
    db.session.add(u)
    db.session.commit()
    flash("You are now following " + username)
    return redirect(url_for('profile', username=username))

@app.route('/unfollow/<username>')
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash("User {0} not found".format(username))
        return redirect(url_for('profile', username=username))
    if user == g.user:
        flash("You can't unfollow yourself!")
        return redirect(url_for("profile", username=username))
    u = g.user.unfollow(user)
    if u is None:
        flash('Cannot unfollow' + username)
        return redirect(url_for('profile',username=username))
    db.session.add(u)
    db.session.commit()
    flash('You have stopped following ' + username)
    return redirect(url_for('profile', username=username))

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