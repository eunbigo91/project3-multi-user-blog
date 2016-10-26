from google.appengine.ext import db

class Comment(db.Model):
    username = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
