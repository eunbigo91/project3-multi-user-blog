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


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(username, password, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(username + password + salt).hexdigest()
    return '%s|%s' % (h, salt)


def valid_pw(username, password, h):
    salt = h.split('|')[1]
    if h == make_pw_hash(username, password, salt):
        return True


def make_secure_val(user_id):
    hash = hmac.new(SECRET, user_id).hexdigest()
    return "%s|%s" % (user_id, hash)


def check_secure_val(secure_val):
    """
        Verifies secure value against secret.
    """
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#check
def valid_user_cookie(user_id, cookie):
    return (cookie == make_secure_val(user_id))


def valid_login(username, password):
    error = False
    if (not USER_RE.match(username) or not PASS_RE.match(password)):
        return None

    user = User.all().filter("username =", username).get()
    if not user:
        return None

    if valid_pw(username, password, user.pw_hash):
        return str(user.key().id())

    else:
        return None

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user_id):
        cookie = make_secure_val(user_id)
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=%s; Path=/' % cookie)
        self.redirect("/blog/welcome")

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

#blog
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    user_id = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Comment(db.Model):
    username = db.StringProperty(required = True)
    comment = db.TextProperty(required = True)
    post_id = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

    @classmethod
    def getNumOfLikes(self, post_id):
        likes = db.GqlQuery("SELECT * FROM Like where post_id = " + str(post_id))
        return likes.count()

    @classmethod
    def checkLikes(self, post_id, user_id):
        likes = db.GqlQuery("SELECT * FROM Like where post_id = " + str(post_id) + "and user_id="+ str(user_id))
        if likes.count() == 0:
            l = Like(user_id=int(user_id), post_id=int(post_id))
            return l

class MainPage(Handler):
    def get(self):
        posts = Post.all().order('-created')
        self.render("blogpage.html", posts=posts)


class NewPostPage(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/blog/login")

    def post(self):
        if not self.user:
            self.redirect("/blog/signup")

        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            post = Post(subject=subject, content=content,
                        user_id=self.user.key().id())
            post.put()
            self.redirect("/blog/%s" %post.key().id())
        else:
            error = "Please write subject and content!!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class PostPage(Handler):
    def get(self, key_id):
        post = Post.get_by_id(int(key_id))
        if not post:
            self.redirect("/blog")
        comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = :id ORDER BY created ASC", id=int(key_id))
        user_id = str(self.user.key().id())
        likes = Like.getNumOfLikes(key_id)
        liked = Like.checkLikes(key_id, self.user.key().id())
        self.render("postpage.html", posts=[post], comments=comments, numOfLikes=likes, liked=liked)

    def post(self, key_id):
        if self.user:
            post = Post.get_by_id(int(key_id))
            if not post:
                self.redirect("/blog")
            comment = self.request.get("comment")
            username = self.request.get("username")
            cmt = Comment(username=username, comment=comment, post_id=int(key_id))
            cmt.put()
            comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = :id ORDER BY created ASC", id=int(key_id))
            likes = Like.getNumOfLikes(key_id)
            liked = Like.checkLikes(key_id, self.user.key().id())
            self.render("postpage.html", posts=[post], comments=comments, numOfLikes=likes, liked=liked)
        else:
            self.redirect("/blog/login")

class EditPostPage(Handler):
    def get(self, key_id):
        if self.user:
            post = Post.get_by_id(int(key_id))
            if post.user_id == self.user.key().id():
                self.render("newpost.html", post_id=key_id, subject=post.subject, content=post.content)
            else:
                self.redirect("/blog")
        else:
            self.redirect("/blog/login")

    def post(self, key_id):
        if not self.user:
            return self.redirect('/blog/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(key_id))
            post = db.get(key)
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' %post.key().id())
        else:
            error = "Please write subject and content!!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class DeletePost(Handler):
    def get(self, key_id):
        if self.user:
            post = Post.get_by_id(int(key_id))
            if post.user_id == self.user.key().id():
                post.delete()
                self.redirect("/blog")
            else:
                self.error(401)
        else:
            self.redirect("/blog/login")

class AddLike(Handler):
    def get(self, key_id):
        if self.user:
            post = Post.get_by_id(int(key_id))
            if self.user.key().id() == post.user_id:
                self.redirect("/blog/" + key_id +
                              "?error=You cannot like your " +
                              "post.!!")
                return

            liked = Like.checkLikes(key_id, self.user.key().id())
            if liked:
                liked.put()
                self.redirect('/blog/%s' %key_id)
            else:
                self.redirect("/blog/" + key_id +
                              "?error=You already liked!")
        else:
            self.redirect("/blog/login")


#user
class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(self, uid):
        """
            This method fetchs User object from database, whose id is {uid}.
        """
        return User.get_by_id(uid)

    @classmethod
    def by_name(self, name):
        u = User.all().filter('username =', name).get()
        return u

    @classmethod
    def login(self, username, pw):
        """
            This method creates a new User in database.
        """
        u = valid_login(username, pw)
        if u:
            return u

    @classmethod
    def register(self, username, pw, email=None):
        """
            This method creates a new User in database.
        """
        pw_hash = make_pw_hash(username, pw)
        return User(username=username,
                    pw_hash=pw_hash,
                    email=email)

class Signup(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        errors = False
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")

        #This parameter always send back username and email
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
            self.redirect('/blog')

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
            self.redirect('/blog/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)

class Welcome(Handler):
    def get(self):
        cookie = self.request.cookies.get("user_id")
        user_id = cookie.split("|",1)[0]
        if not valid_user_cookie(user_id, cookie):
            self.redirect("/blog/signup")
        else:
            self.render("welcome.html", username=self.user.username)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect("/blog/signup")

app = webapp2.WSGIApplication([
    ('/blog/?', MainPage),
    ('/blog/newpost', NewPostPage),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/editpost/([0-9]+)', EditPostPage),
    ('/blog/delete/([0-9]+)', DeletePost),
    ('/blog/addLike/([0-9]+)', AddLike),
    ('/blog/signup', Register),
    ('/blog/login', Login),
    ('/blog/welcome', Welcome),
    ('/blog/logout', Logout)
], debug=True)
