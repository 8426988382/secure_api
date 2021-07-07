import sqlite3

from flask import request
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

        if UserModel.find_by_username(username):
            return {"message": "username is in use"}

        query = 'INSERT INTO users VALUES (NULL, ?, ?)'

        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()

        cursor.execute(query, (username, password))
        connection.commit()
        connection.close()

        return {'message': 'user_created'}, 201


class UserLogin(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('password',
                        type=str,
                        required=True,
                        help='password required')

    def get(self):
        data = UserLogin.parser.parse_args()
        # password = data['password']
        username = request.args.get('username')
        password = request.args.get('password')

        if UserModel.find_by_username(username):

            query = "SELECT * FROM cards WHERE id in (SELECT id from users WHERE username='" + username +\
                    "' AND password='" + password + "')"

            connection = sqlite3.connect('data.db')
            cursor = connection.cursor()

            cards = []
            for _id, card_type, card_number, cvv, account_holder, phone_number in cursor.execute(query):
                cards.append(
                    {
                        "id": _id,
                        "card_type": card_type,
                        "card_no": card_number,
                        "cvv": cvv,
                        "account_holder": account_holder,
                        "phone_number": phone_number,
                    }
                )
            return {"username": username, "cards": cards}, 200

        return {'message': 'username not found'}, 404
