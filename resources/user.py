import sqlite3
import bcrypt
import re
from flask_restful import Resource, reqparse

from models.user import UserModel


class UserRegister(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('username',
                        type=str,
                        required=True,
                        help='username required')

    parser.add_argument('password',
                        type=str,
                        required=True,
                        help='password required')

    @classmethod
    def post(cls):

        try:
            data = cls.parser.parse_args()
            username = data['username']
            password = data['password']

            if username == '' or password == '':
                return {'message': 'invalid username or password'}

            if not check(username):
                return {'message': 'invalid username'}, 400

            if password_check(password):
                if UserModel.find_by_username(username):
                    return {"message": "username is in use"}

                username = username.lower()
                # first method
                # password = password + secret_key
                # hashed_password = sha1(password.encode('utf-8')).hexdigest()
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

                query = 'INSERT INTO users VALUES (NULL, ?, ?)'

                connection = sqlite3.connect('data.db')
                cursor = connection.cursor()

                cursor.execute(query, (username, hashed_password))
                connection.commit()
                connection.close()

                return {'message': 'user_created'}, 201

            return {'message': 'password too weak'}

        except UnableToProcess:
            return {'message', 'unable to process your request'}, 400


class UnableToProcess(Exception):
    pass


def password_check(s):
    l, u, p, d = 0, 0, 0, 0
    if len(s) >= 8:
        for i in s:

            # counting lowercase alphabets
            if i.islower():
                l += 1

                # counting uppercase alphabets
            if i.isupper():
                u += 1

                # counting digits
            if i.isdigit():
                d += 1

                # counting the mentioned special characters
            if i == '@' or i == '$' or i == '_':
                p += 1
    return l >= 1 and u >= 1 and p >= 1 and d >= 1 and l + p + u + d == len(s)


# checking for any special character
def check(string):
    regex = re.compile("['@_!#$%^&*()<>?/|}{~:]")
    if regex.search(string) is None:
        return True
    else:
        return False
