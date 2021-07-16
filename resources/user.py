import sqlite3
import bcrypt
import re

import flask_jwt_extended
from flask import make_response, redirect, url_for
from flask_restful import Resource, reqparse
import flask_wtf
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
)

from models.user import UserModel

parser = reqparse.RequestParser()
parser.add_argument('username',
                    type=str,
                    required=True,
                    help='username required')

parser.add_argument('password',
                    type=str,
                    required=True,
                    help='password required')


class UserRegister(Resource):

    @classmethod
    def post(cls):

        try:
            data = parser.parse_args()
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


class UserLogin(Resource):
    @classmethod
    def post(cls):
        data = parser.parse_args()
        user = UserModel.find_by_username(data['username'])

        if user is None:
            return {'message': 'invalid username or password'}, 401

        if user and bcrypt.checkpw(data['password'].encode(), user.password):
            crsf_token = flask_wtf.csrf.generate_csrf()
            identity = {
                "identity": user.id,
                "csrf_token": crsf_token
            }
            access_token = create_access_token(identity=identity, fresh=True)
            refresh_token = create_refresh_token(user.id)

            response = make_response({
                "access_token": access_token,
                "refresh_token": refresh_token,
                "csrf_token": crsf_token
            })

            response.set_cookie('token', access_token, httponly=True, samesite=None, secure=True)

            return response

        return {
                   "message": "invalid username or password",
               }, 401


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
