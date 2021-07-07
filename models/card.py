import sqlite3

from db import db


class CardModel(db.Model):

    __tablename__ = 'cards'
    id = db.Column(db.Integer)
    card_type = db.Column(db.String(30))
    card_no = db.Column(db.Integer, primary_key=True)
    cvv = db.Column(db.Integer)
    account_holder = db.Column(db.String(80))
    phone_number = db.Column(db.String(20))


    def __init__(self, _id, card_type, card_number, cvv, account_holder, phone_number):
        self.id = _id
        self.card_type = card_type
        self.card_no = card_number
        self.cvv = cvv
        self.account_holder = account_holder
        self.phone_number = phone_number

    @classmethod
    def find_by_card_number(cls, card_number):
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()
        query = 'SELECT * FROM cards WHERE card_no=?'
        result = cursor.execute(query, (card_number,))

        row = result.fetchone()
        print(result, row)

        if row:
            card = cls(*row)
        else:
            card = None
        connection.close()
        return card
