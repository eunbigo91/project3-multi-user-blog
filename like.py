from google.appengine.ext import db

class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

    @classmethod
    def getNumOfLikes(self, post_id):
        likes = db.GqlQuery("SELECT * FROM Like where post_id = " +
                            str(post_id))
        return likes.count()

    @classmethod
    def checkLikes(self, post_id, user_id):
        likes = db.GqlQuery("SELECT * FROM Like where post_id = " +
                            str(post_id) + "and user_id=" + str(user_id))
        if likes.count() == 0:
            l = Like(user_id=int(user_id), post_id=int(post_id))
            return l
