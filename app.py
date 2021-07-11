import os

from flask import Flask
from flask_restful import Api
from flask_jwt import JWT
from flask_cors import CORS
import datetime

from security import authenticate, identity
from resources.user import UserRegister
from resources.card import Card
from db import db
from utils.util import secret_key

uri = os.environ.get('DATABASE_URL', 'sqlite:///data.db')
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(100000)
CORS(app)  # for cross platform interaction
app.secret_key = secret_key
api = Api(app)

db.init_app(app)


@app.before_first_request
def create_tables():
    db.create_all()


"""
this will add an endpoint '/auth' for authentication of the user
"""
jwt = JWT(app, authenticate, identity)  # /auth

api.add_resource(UserRegister, '/user/register')
api.add_resource(Card, '/card/<string:username>')

if __name__ == '__main__':
    app.run()  # debug=True removed
