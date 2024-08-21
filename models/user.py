from database import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    meals = db.relationship('Meal', backref='user')

class Meal(db.Model, UserMixin):
    __tablename__ = 'meals'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable =False)
    calories = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable =False)
    within_diet_plan = db.Column(db.Boolean, nullable=False, default=True)
    description = db.Column(db.String(80), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)