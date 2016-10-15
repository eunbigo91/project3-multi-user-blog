#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import jinja2
import webapp2
import re
import hashlib
import hmac
import random
import string
import cgi

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)
SECRET = "becauesiamhappy"
from google.appengine.ext import db

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
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

def make_user_cookie(user_id):
    hash = hmac.new(SECRET, user_id).hexdigest()
    return "%s|%s" % (user_id, hash)

def valid_user_cookie(user_id, cookie):
    return (cookie == make_user_cookie(user_id))

def valid_login(username, password):
    error = False
    if (not USER_RE.match(username) or not PASS_RE.match(password)):
        return None

    user = User.all().filter("username =", username).get()
    if (not user):
        return None

    if valid_pw(username, password, user.pw_hash):
        return str(user.key().id())

    else:
        return None

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params): #self, file_name, bunch of extra parameters.
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class User(db.Model):
    username = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty

class Signup(Handler):
    def get(self):
        self.render("signup.html")
    def post(self):
        errors = False
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        #This parameter always send back username and email
        params = dict(username=username, email=email)
        user = User.gql("WHERE username = '%s'" % username).get()
        if user:
            params['exist_error'] = "That user already exists."
            errors = True # user already exists
            self.render("signup.html", **params)
        else:
            if not valid_username(username):
                params['error_username'] = "That's not a valid username."
                errors = True
            if not valid_password(password):
                params['error_password'] = "That's not a valid password."
                errors = True
            elif password != verify:
                params['error_verify'] = "Your passwords doesn't match."
                errors = True
            if not valid_email(email):
                params['error_email'] = "That's not a valid email."
                errors = True

            if errors:
                self.render('signup.html', **params)
            else:
                hash = make_pw_hash(username, password)
                user = User(username=username, pw_hash=hash, email=email)
                user.put()
                user_id = str(user.key().id())
                cookie = make_user_cookie(user_id)
                self.response.headers.add_header('Set-Cookie',
                                                 'user_id=%s; Path=/' % cookie)
                self.redirect("/welcome")

class LoginPage(Handler):
    def get(self):
        self.render('login.html')
    def post(self):
        errors = False
        username = self.request.get("username")
        password = self.request.get("password")
        user_id = valid_login(username, password)

        if (user_id == None):
            self.render("login.html",
                        username=cgi.escape(username),
                        error="Invalid login.")
        else:
            cookie = make_user_cookie(user_id)
            self.response.headers.add_header('Set-Cookie',
                                                'user_id=%s; Path=/' % cookie)
            self.redirect("/welcome")

class WelcomePage(Handler):
    def get(self):
        cookie = self.request.cookies.get("user_id")
        user_id = cookie.split("|",1)[0]
        if not valid_user_cookie(user_id, cookie):
            self.redirect("/signup")
        else:
            username = User.get_by_id(int(user_id)).username
            self.render("welcome.html", username=username)

class LogoutPage(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/signup")

app = webapp2.WSGIApplication([
    ('/signup', Signup),
    ('/login', LoginPage),
    ('/welcome', WelcomePage),
    ('/logout', LogoutPage)
], debug=True)
