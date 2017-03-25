import os
import jinja2
import webapp2
import re
import hashlib
import hmac
import random
import string
import cgi
from google.appengine.ext import db
from google.appengine.api import images


from models import User, Post, Comment, Like


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
SECRET = "becauesiamhappy"

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# Create secure value using SECRET
def make_secure_val(user_id):
    hash = hmac.new(SECRET, user_id).hexdigest()
    return "%s|%s" % (user_id, hash)


# Verify secure value against SECRET
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class Handler(webapp2.RequestHandler):
    """
        This is a Handler Class, inherits webapp2.RequestHandler,
        and provides helper methods.
    """
    # This method writes output to client browser
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # This method renders html using template
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Read secure cookie to browser
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Make and add header 'user_id'
    def login(self, user_id):
        cookie = make_secure_val(user_id)
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=%s; Path=/' % cookie)
        self.redirect("/welcome")

    # Remove cookie information
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """
            This method gets executed for each page and
            verity user login status, using cookie informaion
        """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# blog
class MainPage(Handler):
    # Render main page with all posts, sorted by date
    def get(self):
        posts = Post.all().order('-created')
        self.render("blogpage.html", posts=posts)


class NewPostPage(Handler):
    # Render new post page
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    # Create new post and redirect to post page
    def post(self):
        if not self.user:
            self.redirect("/signup")

        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            post = Post(subject=subject, content=content,
                        user_id=self.user.key().id(), username=self.user.username)
            post.put()
            self.redirect("/%s" % post.key().id())
        else:
            error = "Please write subject and content!!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


class PostPage(Handler):
    # Render post page with comments and likes
    def get(self, key_id):
        post = Post.get_by_id(int(key_id))
        if not post:
            self.redirect("/")
        comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = :id" +
                               " ORDER BY created ASC", id=int(key_id))
        likes = Like.getNumOfLikes(key_id)
        if self.user:
            liked = Like.checkLikes(key_id, self.user.key().id())
            self.render("postpage.html", posts=[post], comments=comments,
                        numOfLikes=likes, liked=liked,
                        user_id=self.user.key().id())
        else:
            self.render("postpage.html", posts=[post], comments=comments,
                        numOfLikes=likes, liked=True)

    # Add comment to Comment db and render post page
    def post(self, key_id):
        if self.user:
            post = Post.get_by_id(int(key_id))
            if not post:
                self.redirect("/")
            comment = self.request.get("comment")
            username = self.request.get("username")
            cmt = Comment(username=username, comment=comment,
                          post_id=int(key_id))
            cmt.put()
            comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = " +
                                   ":id ORDER BY created ASC", id=int(key_id))
            likes = Like.getNumOfLikes(key_id)
            liked = Like.checkLikes(key_id, self.user.key().id())
            #self.render("postpage.html", posts=[post], comments=comments,
            #            numOfLikes=likes, liked=liked)
            self.redirect('/%s' % post.key().id())
        else:
            self.redirect("/login")


class EditPostPage(Handler):
    # Render newpost.html with subject and content to edit post
    def get(self, key_id):
        post = Post.get_by_id(int(key_id))
        if not post:
            self.redirect("/")
        if self.user:
            if post.user_id == self.user.key().id():
                self.render("newpost.html", post_id=key_id,
                            subject=post.subject, content=post.content)
            else:
                self.redirect("/")
        else:
            self.redirect("/login")

    # Update post
    def post(self, key_id):
        post = Post.get_by_id(int(key_id))
        if not post:
            self.redirect("/")
        if self.user:
            if post.user_id == self.user.key().id():
                subject = self.request.get('subject')
                content = self.request.get('content')

                if subject and content:
                    key = db.Key.from_path('Post', int(key_id))
                    post = db.get(key)
                    post.subject = subject
                    post.content = content
                    post.put()
                    self.redirect('/%s' % post.key().id())
                else:
                    error = "Please write subject and content!!"
                    self.render("newpost.html", subject=subject, content=content,
                                error=error)
            else:
                self.redirect("/")
        else:
            self.redirect('/login')


class DeletePost(Handler):
    # Delete post
    def get(self, key_id):
        post = Post.get_by_id(int(key_id))
        if not post:
            self.redirect("/")
        if self.user:
            if post.user_id == self.user.key().id():
                post.delete()
                self.redirect("/")
            else:
                self.error(401)
        else:
            self.redirect("/login")


class AddLike(Handler):
    # Add likes to Like db when user click 'like'
    def get(self, key_id):
        post = Post.get_by_id(int(key_id))
        if not post:
            self.redirect("/")
        if self.user:
            if self.user.key().id() == post.user_id:
                self.redirect("/" + key_id +
                              "?error=You cannot like your " +
                              "post.!!")
                return

            liked = Like.checkLikes(key_id, self.user.key().id())
            if liked:
                liked.put()
                self.redirect('/%s' % key_id)
            else:
                self.redirect("/" + key_id +
                              "?error=You already liked!")
        else:
            self.redirect("/login")


class Unlike(Handler):
    # Delete like db when user click 'unlike'
    def get(self, key_id):
        post = Post.get_by_id(int(key_id))
        if not post:
            self.redirect("/")
        if self.user:
            if self.user.key().id() == post.user_id:
                self.redirect("/" + key_id +
                              "?error=You cannot like your " +
                              "post.!!")
                return

            liked = Like.checkLikes(key_id, self.user.key().id())
            if not liked:
                liked = db.GqlQuery("SELECT * FROM Like where post_id = " +
                                    str(key_id) + "and user_id=" +
                                    str(self.user.key().id())).get()
                liked.delete()
                self.redirect('/%s' % key_id)
            else:
                self.redirect("/" + key_id +
                              "?error=You didn't like this post!")
        else:
            self.redirect("/login")


class EditComment(Handler):
    # Render edit comment page
    def get(self, key_id, c_id):
        c = Comment.get_by_id(int(c_id))
        if not c:
            self.redirect("/")
        if self.user:
            if c.username == self.user.username:
                self.render("editcomment.html", comment=c.comment)
            else:
                self.redirect("/")
        else:
            self.redirect("/login")

    # Update comment
    def post(self, key_id, c_id):
        post = Post.get_by_id(int(key_id))
        c = Comment.get_by_id(int(c_id))
        if not c:
            self.redirect("/")
        if self.user:
            comment = self.request.get('comment')
            if c.username == self.user.username:
                if comment:
                    c = Comment.get_by_id(int(c_id))
                    c.comment = comment
                    c.put()
                    self.redirect('/%s' % post.key().id())
                else:
                    error = "Please write comment!!"
                    self.render("editcomment.html", comment=comment)
            else:
                self.redirect('/%s' % post.key().id())
        else:
            self.redirect("/login")


class DeleteComment(Handler):
    # Delete comment
    def get(self, key_id, c_id):
        post = Post.get_by_id(int(key_id))
        c = Comment.get_by_id(int(c_id))
        if not post:
            self.redirect("/")
        if not c:
            self.redirect("/")
        if self.user:
            if c.username == self.user.username:
                c.delete()
                self.redirect('/%s' % post.key().id())
            else:
                self.error(401)
        else:
            self.redirect("/login")


# User
class Signup(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        errors = False
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")

        # This parameter always send back username and email
        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            errors = True
        if not valid_password(self.password):
            params['error_password'] = "That's not a valid password."
            errors = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords doesn't match."
            errors = True
        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            errors = True

        if errors:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        # Make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(str(u.key().id()))
            self.redirect('/welcome')


class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        errors = False
        username = self.request.get("username")
        password = self.request.get("password")

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class Welcome(Handler):
    def get(self):
        cookie = self.request.cookies.get("user_id")
        if not check_secure_val(cookie):
            self.redirect("/signup")
        else:
            self.render("welcome.html", username=self.user.username)


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect("/signup")

app = webapp2.WSGIApplication([
    ('/?', MainPage),
    ('/newpost', NewPostPage),
    ('/([0-9]+)', PostPage),
    ('/editpost/([0-9]+)', EditPostPage),
    ('/delete/([0-9]+)', DeletePost),
    ('/addlike/([0-9]+)', AddLike),
    ('/unlike/([0-9]+)', Unlike),
    ('/editcomment/([0-9]+)/([0-9]+)', EditComment),
    ('/deletecomment/([0-9]+)/([0-9]+)', DeleteComment),
    ('/signup', Register),
    ('/login', Login),
    ('/welcome', Welcome),
    ('/logout', Logout)
], debug=True)
