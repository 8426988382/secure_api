import sqlite3
import re
from utils.util import f

from flask_restful import Resource, reqparse
from flask_jwt import jwt_required, current_identity

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
            identity = current_identity
            if not check(username):
                return {'message': 'invalid username or password'}, 401
            username = username.lower()

            user = UserModel.find_by_username(username)

            if user:

                if user.id != identity.id or user.username != identity.username:
                    return {'message': 'invalid token'}, 401

                # bad query
                # query = "SELECT * FROM cards WHERE id in (SELECT id FROM users WHERE username='" + username + "')"

                query = "SELECT * FROM cards WHERE id in (SELECT id FROM users WHERE username=?)"

                connection = sqlite3.connect('data.db')
                cursor = connection.cursor()

                cards = []
                for _id, card_type, card_number, cvv, account_holder, phone_number, expiry_date in cursor.execute(query,
                                                                                                     (username,)):
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
                return {'message': 'no user found'}

        except ErrorException:
            return {'message': 'some error has occurred'}

    @classmethod
    @jwt_required()
    def post(cls, username):

        try:
            identity = current_identity
            if not check(username):
                return {'message': 'invalid username or password'}, 401
            username = username.lower()
            user = UserModel.find_by_username(username)

            if user:
                if user.id != identity.id or user.username != identity.username:
                    return {'message': 'invalid token'}

                data = Card.parser.parse_args()

                _id = user.id
                card_type = f.encrypt(data['card_type'].encode())
                card_no = f.encrypt(data['card_no'].encode())
                cvv = f.encrypt(data['cvv'].encode())
                account_holder = f.encrypt(data['account_holder'].encode())
                phone_number = f.encrypt(data['phone_number'].encode())
                expiry_date = f.encrypt(data['expiry_date'].encode())

                data = {_id, card_type, card_no, cvv, account_holder, phone_number, expiry_date}
                print(data)

                # check if card with the provided number exists or not in the database
                if CardModel.find_by_card_number(card_no):
                    return {'message': 'Card already exists'}

                query = "INSERT INTO cards VALUES (?, ?, ?, ?, ?, ?, ?)"
                connection = sqlite3.connect('data.db')
                cursor = connection.cursor()
                cursor.execute(query, (_id, card_type, card_no, cvv, account_holder, phone_number, expiry_date))

                connection.commit()
                connection.close()
                return {'message': 'card added'}, 201
            else:
                return {'message': 'no user exist'}, 404
        except TokenInvalidException:
            return {'message': 'token invalid or not provided'}


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
