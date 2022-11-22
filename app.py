import os
from flask import Flask, render_template, flash, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, SelectField
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.widgets import TextArea
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user


basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SECRET_KEY'] = 'AS#$54744#@#SDFadqwef'
db = SQLAlchemy(app)
migrate = Migrate(app, db)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
	return Users.query.get(int(user_id))

################MODEL###############
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Posts', backref='users')

    @property
    def password(self):
            raise AttributeError('password is not readable attribute')
        
    @password.setter
    def password(self, password):
            self.password_hash = generate_password_hash(password)

    def verify_password(self,password):
            return check_password_hash(self.password_hash, password)

    def __repr__(self):
            return '<Name %r>' % self.name


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    author = db.Column(db.String(150), nullable=False)
    content = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    post = db.relationship('Posts', backref='category')
    

############FORMS####################
#Registration form:
class UserForm(FlaskForm):
    username = StringField("Whats your username", validators=[DataRequired()])
    email = StringField("Whats your email", validators=[DataRequired()])
    password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2', message='Passwords Must Match!')])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField("Submit")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

class PostForm(FlaskForm):
    title = StringField("Post title", validators=[DataRequired()])
    content = StringField("Post content", validators=[DataRequired()])
    category = StringField("Post category")
    submit = SubmitField("Submit")

###########ROUTES####################

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username = form.username.data).first()
        if user:
        #Checking password hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Login Succesfull!!")
                return redirect(url_for('posts'))
            else:
                flash("Wrong Password - Try Again!")
        else:
            flash("That User Doesn't Exist! Try Again...")

    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	flash("You Have Been Logged Out!")
	return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
            user = Users(username = form.username.data, email = form.email.data,password_hash = hashed_pw )
            db.session.add(user)
            db.session.commit()
            form.email.data = ''
            form.username.data = ''	
            form.password_hash.data = ''	
            flash("User Added Successfully!")
        else:
            flash("Something went wrong, please try again")
    return render_template("register.html", form = form)
    

@app.route('/posts', methods=['GET', 'POST'])
@login_required
def posts():
    category = None
    posts = Posts.query.order_by(Posts.date_added)
    for post in posts:
        category = Category.query.filter_by(id = post.category_id).first()

    return render_template("posts.html", posts = posts, category = category)

@app.route('/add-post', methods=['GET', 'POST'])
@login_required
def add_post():
    form = PostForm()
    id = current_user.id
    all_categories = Category.query.all() #Padarysi su JS dropdown lista
    if form.validate_on_submit():
        category = Category.query.filter_by(title = form.category.data).first()
        if category:    
            post = Posts(title = form.title.data, content = form.content.data, user_id = current_user.id, author = current_user.username, category_id = category.id)
            db.session.add(post)
            db.session.commit()
            flash("Post added sucessfully!")
        else:
            category = Category(title = form.category.data)
            db.session.add(category)
            db.session.commit()
            post = Posts(title = form.title.data, content = form.content.data, user_id = current_user.id, author = current_user.username, category_id = category.id)
            db.session.add(post)
            db.session.commit()
            flash("Post added sucessfully!")
        
    form.title.data = ''
    form.content.data = ''
    form.category.data = ''
    
    return render_template("add_post.html", form = form, all_categories = all_categories)

@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    all_categories = Category.query.order_by(Category.id)
    post = Posts.query.get_or_404(id)
    category = Category.query.get_or_404(post.category_id)
    form = PostForm()
    id = current_user.id
    if id == post.user_id:
        if form.validate_on_submit():
            category = Category.query.filter_by(title = form.category.data).first()
            if category:
                post.title = form.title.data
                post.content = form.content.data
                post.category_id = category.id
                db.session.add(post)
                db.session.commit()
                flash("Post updated sucessfully!")
                return redirect(url_for('posts', id = post.id, all_categories = all_categories))
            else:
                post.title = form.title.data
                post.content = form.content.data
                category = Category(title = form.category.data)
                db.session.add(category)
                db.session.commit()
                post.category_id = category.id
                db.session.add(post)
                db.session.commit()
                flash("Post updated sucessfully!")
                return redirect(url_for('posts', id = post.id, all_categories = all_categories))
    else:
        flash("You cannot edit this post!")
        return redirect(url_for('posts', id = post.id))
    form.title.data = post.title
    form.content.data = post.content
    form.category.data = category.title
    return render_template("post_edit.html", form = form, all_categories = all_categories)

@app.route('/posts/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    id = current_user.id
    if id == post_to_delete.user_id:
        try:
            db.session.delete(post_to_delete)
            db.session.commit()
            flash("Post deleted Sucessfully!")
            posts = Posts.query.order_by(Posts.date_added)
            return render_template("posts.html", posts = posts)
        except:
            flash("Post was not deleted, try again!")
            posts = Posts.query.order_by(Posts.date_added)
            return render_template("posts.html", posts = posts)

    else:
        flash("You are not allowed to delete this post!")
        posts = Posts.query.order_by(Posts.date_added)
        return redirect(url_for('posts', id = post_to_delete.id))

@app.route('/categories', methods=['GET', 'POST'])
@l

############CUSTOM ERRORS############ 

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500


if __name__ == "__main__":
    app.run(debug=True)