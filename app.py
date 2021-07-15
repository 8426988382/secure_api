import os

from flask import Flask
from flask_restful import Api
from flask_jwt import JWT
from flask_jwt_extended import JWTManager
from flask_cors import CORS
import datetime

from security import authenticate, identity
from resources.user import UserRegister, UserLogin
from resources.card import Card
from db import db
from utils.util import secret_key
from csrf import csrf

uri = os.environ.get('DATABASE_URL', 'sqlite:///data.db')
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(100000)
CORS(app)  # for cross platform interaction
app.secret_key = secret_key


def csrf_exempt_my_resource(view):
    if issubclass(view.view_class, UserRegister):
        return csrf.exempt(view)
    elif issubclass(view.view_class, UserLogin):
        return csrf.exempt(view)
    return view


csrf.init_app(app)
jwt = JWTManager(app)
api = Api(app, decorators=[csrf_exempt_my_resource])
db.init_app(app)


@app.before_first_request
def create_tables():
    db.create_all()


"""
this will add an endpoint '/auth' for authentication of the user
"""
# jwt = JWT(app, authenticate, identity)  # /auth
"""
using flask JWT extended
"""


api.add_resource(UserRegister, '/user/register')
api.add_resource(Card, '/card/<string:username>')
api.add_resource(UserLogin, '/auth')

if __name__ == '__main__':
    app.run()  # debug=True removed
