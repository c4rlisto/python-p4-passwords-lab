# server/config.py

import os

class Config:
    SECRET_KEY = os.urandom(24)  # Random secret key for sessions
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'  # SQLite database URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable modification tracking for SQLAlchemy
