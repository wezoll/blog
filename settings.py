import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

SECRET_KEY = os.urandom(36)
SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
SQLALCHEMY_TRACK_MODIFICATIONS = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS') == 'True'

REMEMBER_COOKIE_DURATION = timedelta(minutes=5)

# MAIL_USERNAME = os.getenv('EMAIL_USER')
# MAIL_PASSWORD = os.getenv('EMAIL_PASS')
# MAIL_SERVER = 'smtp.yandex.ru'
# MAIL_PORT = 465
# MAIL_USE_SSL = True
# MAIL_DEFAULT_SENDER = os.getenv('Wezoll Support', 'wezollx@yandex.kz')
