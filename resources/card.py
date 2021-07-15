import sqlite3
import re
import jwt
import base64

from flask import request, make_response
from utils.util import f, secret_key

from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity

from models.user import UserModel
from models.card import CardModel


class Card(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("card_type",
                        type=str,
                        required=True,
                        help='card_number is missing')
    parser.add_argument("card_no",
                        type=str,
                        required=True,
                        help='card_number is missing')
    parser.add_argument("cvv",
                        type=str,
                        required=True,
                        help='cvv is missing')
    parser.add_argument("account_holder",
                        type=str,
                        required=True,
                        help='id is missing')
    parser.add_argument("phone_number",
                        type=str,
                        required=True,
                        help='id is missing')
    parser.add_argument("expiry_date",
                        type=str,
                        required=True,
                        help='expiry date is missing')

    @classmethod
    @jwt_required()
    def get(cls, username):
        try:
            if not check(username):
                return {'message': 'invalid username or password'}, 401
            username = username.lower()

            identity = get_jwt_identity()['identity']
            user = UserModel.find_by_username(username)
            user_identity = UserModel.find_by_userid(identity)

            if user:
                if user.id != user_identity.id or user.username != user_identity.username:
                    return {'message': 'invalid token'}, 401

                # bad query
                # query = "SELECT * FROM cards WHERE id in (SELECT id FROM users WHERE username='" + username + "')"

                query = "SELECT * FROM cards WHERE id in (SELECT id FROM users WHERE username=?)"

                connection = sqlite3.connect('data.db')
                cursor = connection.cursor()

                cards = []
                for _id, card_type, card_number, cvv, account_holder, phone_number, expiry_date in cursor.execute(query,
                                                                                                                  (
                                                                                                                          username,)):
                    cards.append(
                        {
                            "id": _id,
                            "card_type": f.decrypt(card_type).decode(),
                            "card_no": f.decrypt(card_number).decode(),
                            "cvv": f.decrypt(cvv).decode(),
                            "account_holder": f.decrypt(account_holder).decode(),
                            "phone_number": f.decrypt(phone_number).decode(),
                            "expiry_date": f.decrypt(expiry_date).decode()
                        }
                    )
                return {"username": username, "cards": cards}, 200
            else:
                return {'message': 'no user found'}, 404

        except ErrorException:
            return {'message': 'some error has occurred'}

    @classmethod
    @jwt_required()
    def post(cls, username):

        try:
            identity = get_jwt_identity()['identity']
            verify_csrf_token = request.headers['X-CSRFToken']

            token = request.cookies.get('token')

            if token_check(token) == -1:
                return {'message': 'invalid token in token check'}, 401

            data = jwt.decode(token, secret_key, algorithms=['HS256'])

            sub = data.get('sub')

            if sub is None:
                return {'message': 'invalid token'}, 401

            csrf_token = sub.get('csrf_token')

            if csrf_token is None:
                return {'message': 'token missing'}, 401

            if csrf_token != verify_csrf_token:
                return {'message': 'login required'}, 401

            if not check(username):
                return {'message': 'invalid username or password'}, 401

            username = username.lower()
            user = UserModel.find_by_username(username)
            user_identity = UserModel.find_by_userid(identity)

            if user:
                if user.id != user_identity.id or user.username != user_identity.username:
                    return {'message': 'invalid token'}, 401

                data = Card.parser.parse_args()

                _id = user.id
                card_type = f.encrypt(data['card_type'].encode())
                card_no = f.encrypt(data['card_no'].encode())
                cvv = f.encrypt(data['cvv'].encode())
                account_holder = f.encrypt(data['account_holder'].encode())
                phone_number = f.encrypt(data['phone_number'].encode())
                expiry_date = f.encrypt(data['expiry_date'].encode())

                # check if card with the provided number exists or not in the database
                if CardModel.find_by_card_number(card_no):
                    return {'message': 'Card already exists'}

                query = "INSERT INTO cards VALUES (?, ?, ?, ?, ?, ?, ?)"
                connection = sqlite3.connect('data.db')
                cursor = connection.cursor()
                cursor.execute(query, (_id, card_type, card_no, cvv, account_holder, phone_number, expiry_date))

                connection.commit()
                connection.close()
                response = make_response(
                    {'message': 'card added'},
                    201
                )
                response.headers.add('Access-Control-Allow-Credentials', True)
                return response
            else:
                return {'message': 'no user exist'}, 404
        except TokenInvalidException:
            return {'message': 'token invalid or not provided'}, 400


class TokenInvalidException(Exception):
    pass


class ErrorException(Exception):
    pass


# checking for any special character
def check(string):
    regex = re.compile("['@_!#$%^&*()<>?/|}{~:]")
    if regex.search(string) is None:
        return True

    else:
        return False


def token_check(token):
    try:
        # 1. verify that the token has three components
        components = token.split('.')
        signature = components[2]
        if len(components) != 3:
            return -1

        # 2. check algorithm
        header = jwt.get_unverified_header(token)
        algorithm = header.get('alg')
        if algorithm is None or algorithm == 'RS256':
            return -1

        # verifying the signature
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])

        encoded_jwt = jwt.encode(
            payload,
            secret_key,
            algorithm='HS256',
            headers=header
        )

        if encoded_jwt != token:
            return -1
        return 1
    except Exception as e:
        print(e.args)
        return -1


def is_base64(s):
    try:
        return base64.b64encode(base64.b64decode(s)) == s
    except Exception:
        return False
