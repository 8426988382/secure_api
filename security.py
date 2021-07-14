import bcrypt
from models.user import UserModel


def authenticate(username, password):
    user = UserModel.find_by_username(username)

    # first method
    # password = password + secret_key
    # hashed_password = sha1(password.encode('utf-8')).hexdigest()

    if user and bcrypt.checkpw(password.encode(), user.password):
        return user


def identity(payload):
    _id = payload['identity']
    return UserModel.find_by_userid(_id)
