import sqlite3

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

        data = cls.parser.parse_args()
        username = data['username']
        password = data['password']

        username = username.lower()

        if password_check(password):
            if UserModel.find_by_username(username):
                return {"message": "username is in use"}

            query = 'INSERT INTO users VALUES (NULL, ?, ?)'

            connection = sqlite3.connect('data.db')
            cursor = connection.cursor()

            cursor.execute(query, (username, password))
            connection.commit()
            connection.close()

            return {'message': 'user_created'}, 201

        return {'message': 'password too weak'}


# class UserLogin(Resource):
#     @classmethod
#     def get(cls):
#         username = request.args.get('username')
#         password = request.args.get('password')
#
#         if username is None:
#             return {'message': 'invalid username'}
#         if password is None:
#             return {'message': 'password cannot be empty'}
#
#         if UserModel.find_by_username(username):
#
#             query = "SELECT * FROM cards WHERE id in (SELECT id from users WHERE username='" + username + \
#                     "' AND password='" + password + "')"
#
#             connection = sqlite3.connect('data.db')
#             cursor = connection.cursor()
#
#             cards = []
#             for _id, card_type, card_number, cvv, account_holder, phone_number in cursor.execute(query):
#                 cards.append(
#                     {
#                         "id": _id,
#                         "card_type": card_type,
#                         "card_no": card_number,
#                         "cvv": cvv,
#                         "account_holder": account_holder,
#                         "phone_number": phone_number,
#                     }
#                 )
#             return {"username": username, "cards": cards}, 200
#
#         return {'message': 'username not found'}, 404


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
