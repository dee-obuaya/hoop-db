import sys
from models import User
from main import *


def create_user():
    key = call_key()
    print(key)
    fernet = Fernet(key)

    try:
        user = User(
            username='james.ip',
            password=fernet.encrypt('james@hoop'.encode()),
            department='IP',
            privileges='Admin'
        )

        user.insert()
        print('User created')
    except:
        print(sys.exc_info())


app.app_context().push()
create_user()
