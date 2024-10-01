from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    account_id = db.Column(db.String(50), nullable=False)
    provider_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=False, nullable=False)  # New field
    regions = db.relationship('Region', backref='account', lazy=True)


class Region(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    account_id = db.Column(db.Integer, db.ForeignKey('account.id'), nullable=False)
    services = db.relationship('Service', backref='region', lazy=True)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    region_id = db.Column(db.Integer, db.ForeignKey('region.id'), nullable=False)
    account_id = db.Column(db.Integer, db.ForeignKey('account.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    user = db.Column(db.String(50), nullable=True)
    credentials = db.Column(db.String(100), nullable=True)
    project_name = db.Column(db.String(50), nullable=True)  # Add a new column for project name
    status = db.Column(db.String(50), nullable=True)

