import sqlite3

from db import db


class CardModel(db.Model):
    __tablename__ = 'cards'
    id = db.Column(db.Integer)
    card_type = db.Column(db.String(30))
    card_no = db.Column(db.String, primary_key=True)
    cvv = db.Column(db.String)
    account_holder = db.Column(db.String(80))
    phone_number = db.Column(db.String(20))
    expiry_date = db.Column(db.String)

    def __init__(self, _id, card_type, card_number, cvv, account_holder, phone_number, expiry_date):
        self.id = _id
        self.card_type = card_type
        self.card_no = card_number
        self.cvv = cvv
        self.account_holder = account_holder
        self.phone_number = phone_number
        self.expiry_date = expiry_date

    @classmethod
    def find_by_card_number(cls, card_number):
        try:
            connection = sqlite3.connect('data.db')
            cursor = connection.cursor()
            query = 'SELECT * FROM cards WHERE card_no=?'
            result = cursor.execute(query, (card_number,))

            row = result.fetchone()

            if row:
                card = cls(*row)
            else:
                card = None
            connection.close()
            return card
        except ErrorException:
            return {"message": "some error has occurred"}


class ErrorException(Exception):
    pass
