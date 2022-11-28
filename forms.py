from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField,SelectField, SearchField
from wtforms.validators import DataRequired, EqualTo
from wtforms.widgets import TextArea


class UserForm(FlaskForm):
    username = StringField("Whats your username:", validators=[DataRequired()])
    email = StringField("Whats your email:", validators=[DataRequired()])
    password_hash = PasswordField('Password:', validators=[DataRequired(), EqualTo('password_hash2', message='Passwords Must Match!')])
    password_hash2 = PasswordField('Confirm Password:', validators=[DataRequired()])
    submit = SubmitField("Submit")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

class PostForm(FlaskForm):
    title = StringField("Post title", validators=[DataRequired()])
    content = StringField("Post content", validators=[DataRequired()],widget=TextArea())
    category = SelectField("")
    new_category = StringField("Create new category")
    submit = SubmitField("Submit")

class CategoryUpdateForm(FlaskForm):
    title = StringField("Category", validators=[DataRequired()])
    submit = SubmitField("Submit")

class CategoryFilterForm(FlaskForm):
    title = SelectField("Filter Posts by Category title:")
    submit = SubmitField("Filter")

class PostSearchForm(FlaskForm):
    title = SearchField("Search for post title:")
    submit = SubmitField("Search")
