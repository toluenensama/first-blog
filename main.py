from flask import Flask, render_template, redirect, url_for, flash,g,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm,UserForm,LogForm,CommentsForm
from flask_gravatar import Gravatar
from flask_bcrypt import Bcrypt
from functools import wraps
import os
from dotenv import find_dotenv,load_dotenv
from waitress import serve

dotenv_path = find_dotenv()
load_dotenv(dotenv_path)


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
ckeditor = CKEditor()
ckeditor.init_app(app)
Bootstrap(app)
flask_bcrypt =Bcrypt()
flask_bcrypt.init_app(app)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy()
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# User model
class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = db.relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comment", back_populates="comment_author")

# BlogPost model
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # Corrected reference
    author = db.relationship("Users", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = db.relationship("Comment", back_populates="parent_post")  # Fixed class name

# Comment model
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))  # Corrected foreign key reference
    comment_author = db.relationship("Users", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))  # Corrected foreign key type
    parent_post = db.relationship("BlogPost", back_populates="comments")

# Create the tables
with app.app_context():
    db.create_all()


with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return  db.session.get(Users, int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.get_id() != '1':
            return abort(403)
        return f(*args, **kwargs)        
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts,
                           logged_in = current_user.is_authenticated,
                           user_id=current_user.get_id(),
                           user=current_user)


@app.route('/register',methods=["POST","GET"])
def register():
    form = UserForm()
    if form.validate_on_submit():
        hash_password = flask_bcrypt.generate_password_hash(form.password.data, 
                                               10)

        if Users.query.filter_by(email = form.email.data).first():
            flash("Email already registered by you")
            return redirect("login")
        elif Users.query.filter_by(name = form.name.data).first():
            flash("Name already taken")
        else:
            new_user = Users(
                email = form.email.data,
                password = hash_password,
                name = form.name.data
            )
            db.session.add(new_user)
            db.session.commit()
            
            login_user(new_user)
            return redirect(url_for("get_all_posts"))

    
    
    return render_template("register.html",form=form)


@app.route('/login',methods=["POST","GET"])
# @login_required
def login():
    form = LogForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if not user:
            flash("Email not Registered")
            return(redirect(url_for('register')))
        else:
            user_password = user.password
            if flask_bcrypt.check_password_hash(user_password,form.password.data):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Incorrect Password")
                return redirect(url_for('login'))

    return render_template("login.html",form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=["POST","GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentsForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You have to have an account to comment")
            return redirect(url_for("login")) 
        comment = Comment(
            text = form.text.data,
            comment_author = current_user,
            parent_post = requested_post
        )
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for("show_post",post_id=post_id))
    comment = Comment.query.filter_by(post_id=post_id).all()
    return render_template("post.html", post=requested_post,
                        user_id=current_user.get_id(),user=current_user,form=form,comments=comment)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods=["POST","GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))




if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000)
