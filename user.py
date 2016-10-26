from google.appengine.ext import db
import hmac
import random
import hashlib
import string
import re

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(username, password, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(username + password + salt).hexdigest()
    return '%s|%s' % (h, salt)


def valid_pw(username, password, h):
    salt = h.split('|')[1]
    if h == make_pw_hash(username, password, salt):
        return True


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


class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(self, uid):
        """
            Fetch User object from database, whose id is {uid}
        """
        return User.get_by_id(uid)

    @classmethod
    def by_name(self, name):
        u = User.all().filter('username =', name).get()
        return u

    @classmethod
    def login(self, username, pw):
        """
            Create a new User in database.
        """
        u = valid_login(username, pw)
        if u:
            return u

    @classmethod
    def register(self, username, pw, email=None):
        """
            Create a new User in database.
        """
        pw_hash = make_pw_hash(username, pw)
        return User(username=username,
                    pw_hash=pw_hash,
                    email=email)
