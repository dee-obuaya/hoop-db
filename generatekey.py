import sys
from cryptography.fernet import Fernet
from models import User
from main import *


def create_key():
    """
    Generates a key and save it into a file
    """
    key = Fernet.generate_key()

    with open('fernet.key', 'wb') as key_file:
        key_file.write(key)

    print('Key created')


def create_user():
    def call_key():
        '''
        Loads the key from the file where it is stored.
        '''
        return open('fernet.key', 'rb').read()

    key = call_key()
    fernet = Fernet(key)

    try:
        user = User(
            username='admin',
            password=fernet.encrypt('admin'.encode()),
            department='IP',
            privileges='Admin'
        )

        user.insert()
        print('User created')
    except:
        print(sys.exc_info())


create_key()
app.app_context().push()
create_user()
