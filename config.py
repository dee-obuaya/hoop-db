import os
import random
import string
from decouple import config

def id_generator(size=32, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


SECRET_KEY = id_generator()

# Grabs the folder where the script runs.
basedir = os.path.abspath(os.path.dirname(__file__))

# Enable debug mode.
DEBUG = True

# Upload folder
UPLOAD_FOLDER = 'static/files'

# Flask Admin
FLASK_ADMIN_SWATCH = 'flatly'

# Connect to the database
SQLALCHEMY_DATABASE_URI = 'postgresql://{}:{}@{}/{}'.format(config('db_user'), config('db_password'), config('db_host'), config('db_name'))
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ENGINE_OPTIONS = {
    "max_overflow": 15,
    "pool_pre_ping": True,
    "pool_recycle": 60 * 60,
    "pool_size": 30,
}
