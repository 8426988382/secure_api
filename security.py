from hashlib import sha1

from models.user import UserModel
from utils.util import secret_key


def authenticate(username, password):
    user = UserModel.find_by_username(username)

    password = password + secret_key
    hashed_password = sha1(password.encode('utf-8')).hexdigest()

    if user and user.password == hashed_password:
        return user


def identity(payload):
    _id = payload['identity']
    return UserModel.find_by_userid(_id)
