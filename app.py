import os
from flask import Flask, render_template, flash, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from forms import UserForm, LoginForm, PostForm,CategoryUpdateForm, CategoryFilterForm, PostSearchForm


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
    category = db.relationship('Category', backref='users')

    @property
    def password(self):
            raise AttributeError('password is not readable attribute')
        
    @password.setter
    def password(self, password):
            self.password_hash = generate_password_hash(password)

    def verify_password(self,password):
            return check_password_hash(self.password_hash, password)

    def __repr__(self):
            return '<Username %r>' % self.username


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    author = db.Column(db.String(150), nullable=False)
    content = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    category_title = db.Column(db.String)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    post = db.relationship('Posts', backref='category')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))


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
            return(redirect(url_for('login')))
        else:
            flash("Something went wrong, please try again")
    return render_template("register.html", form = form)
    

@app.route('/posts', methods=['GET', 'POST'])
@login_required
def posts():
    form = PostSearchForm()
    if form.validate_on_submit():
        post = Posts.query.filter_by(title = form.title.data).first()
        if post:
            posts = Posts.query.filter_by(title = post.title)
            return render_template("posts_filtered.html", posts = posts, form = form)
        else:
            posts = Posts.query.order_by(Posts.date_added)
            flash("No post found with this name, please try again!")
            return render_template("posts.html", posts = posts, form = form)
    posts = Posts.query.order_by(Posts.date_added)
    return render_template("posts.html", posts = posts, form = form)

@app.route('/add-post', methods=['GET', 'POST'])
@login_required
def add_post():
    form = PostForm()
    categories = Category.query.all()
    id = current_user.id
    form.category.choices = [(g.title) for g in categories]
 
    if form.validate_on_submit():
        if form.new_category.data != '':
            new_category = Category(title = form.new_category.data, user_id = id)
            db.session.add(new_category)
            db.session.commit()
            post = Posts(title = form.title.data, author= current_user.username, content = form.content.data, user_id = id, category_id = new_category.id, category_title = new_category.title)
            db.session.add(post)
            db.session.commit()
            flash("Post and category were added sucessfully!")
        else:
            category = Category.query.filter_by(title = form.category.data).first()
            post = Posts(title = form.title.data, author= current_user.username, content = form.content.data, user_id = id, category_id = category.id, category_title = category.title)
            db.session.add(post)
            db.session.commit()
            flash("Post was added sucessfully!")
    form.title.data = ''
    form.content.data = ''
    form.new_category.data = ''
    return render_template("post_add.html", form = form)

@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    form = PostForm()
    all_categories = Category.query.all()
    form.category.choices =[(g.title) for g in all_categories]
    post = Posts.query.get_or_404(id)
    id = current_user.id
    category = Category.query.get_or_404(post.category_id)
    if id == post.user_id:
        if form.validate_on_submit():
            if form.new_category.data != '':
                new_category = Category(title = form.new_category.data, user_id = id)
                db.session.add(new_category)
                db.session.commit()
                post.title = form.title.data
                post.content = form.content.data
                post.category_id = new_category.id
                post.used_id = id
                post.category_title = new_category.title
                db.session.add(post)
                db.session.commit()
                flash("Post updated sucessfully! New category added")
                return redirect(url_for('posts', id = post.id, all_categories = all_categories))
            else:
                category = Category.query.filter_by(title = form.category.data).first()
                post.title = form.title.data
                post.content = form.content.data
                post.category_id = category.id
                post.used_id = id
                post.category_title = category.title
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
    return render_template("post_edit.html", form = form)

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
            return redirect(url_for('posts', id = post_to_delete.id))
        except:
            flash("Post was not deleted, try again!")
            posts = Posts.query.order_by(Posts.date_added)
            return redirect(url_for('posts', id = post_to_delete.id))

    else:
        flash("You are not allowed to delete this post!")
        posts = Posts.query.order_by(Posts.date_added)
        return redirect(url_for('posts', id = post_to_delete.id))

@app.route('/categories', methods=['GET', 'POST'])
def categories():
    form = CategoryFilterForm()
    categories = Category.query.order_by(Category.id)
    form.title.choices = [(g.title) for g in categories]
    if form.validate_on_submit():
        title = form.title.data
        posts = Posts.query.filter_by(category_title = title)
        return render_template("posts_filtered.html", form = form, categories = categories, posts = posts)
    else:
        return render_template("categories.html", categories = categories, form = form)   

@app.route('/categories/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_category(id):
    form = CategoryUpdateForm()
    category = Category.query.get_or_404(id)
    post = Posts.query.get_or_404(category.id)
    if form.validate_on_submit():
        category.title = form.title.data
        db.session.add(category)
        db.session.commit()
        post.category_title = form.title.data
        db.session.add(post)
        db.session.commit()
        flash("Category updated sucessfully!")
        return redirect(url_for('categories', form = form, id = category.id))
    form.title.data = category.title
    return render_template("category_edit.html", form = form, id = category.id)

@app.route('/add-category', methods=['GET', 'POST'])
@login_required
def add_category():
    form = CategoryUpdateForm()
    id = current_user.id
    if form.validate_on_submit():
        category = Category(title = form.title.data, user_id = id)
        form.title.data = ''
        db.session.add(category)
        db.session.commit()
        flash("Category created sucesfully!")

    return render_template("category_add.html", form = form)

@app.route('/categories/delete/<int:id>')
@login_required
def delete_category(id):
    form = CategoryUpdateForm()
    category_to_delete = Category.query.get_or_404(id)
    id = current_user.id
    posts_to_edit = Posts.query.filter_by(category_id = category_to_delete.id)
    if id == category_to_delete.user_id:
        try:
            for post in posts_to_edit:
                post.category_id = 1
                post.category_title = "Uncategorized"
                db.session.add(post)
                db.session.commit()
            db.session.delete(category_to_delete)
            db.session.commit()
            flash("Category deleted Sucessfully!")
            categories = Category.query.order_by(Category.id)
            return render_template("categories.html", categories = categories)
        except:
            flash("Category was not deleted, try again!")
            categories = Category.query.order_by(Category.id)
            return render_template("categories.html", categories = categories, form = form)

    else:
        flash("You are not allowed to delete this category!")
        categories = Category.query.order_by(Category.id)
        return redirect(url_for('cateogories', id = category_to_delete.id, categories = categories))


############CUSTOM ERRORS############ 

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500


if __name__ == "__main__":
    app.run(debug=True)