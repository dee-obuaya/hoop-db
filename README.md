# HOOP DATABASE
A simple platform to view, interact and make changes to Hoop Telecoms Databases

## Getting Started

### Installing Dependencies
##### Python 3.10.6
Follow instructions to install the latest version of python for your platform in the [python docs](https://www.python.org/downloads/)

##### Virtual Environment
I recommend you work within a virtual environment when using python for your projects. This is due to dependency and comaptibility issues that can arrise with conflicting versions. 
For instructions on how to set up a virtual environment click [here](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/)

##### PIP Dependencies
Once your virtual environment is up an running, cd into the root directory of the folder and run:

`pip install -r requirements.txt`

This installs all the required packages needed for this project.

### Setting up your database
In your database of choice, create a database you will use for this project.

##### Database variables
In the root directory, create a .env file which config.py will read your database variables from. These variables are:
- db: this is the databse server you are working with.
- db_host: your database host.
- db_name: name of the database you created earlier.
- db_user: the user of your database server
- db_password: the password for the user of your database server

```
db="postgresql"
db_host="127.0.0.1:5432"
db_name=name of your database
db_user=your database user
db_password=your database password
```
##### Flask Migrate
All tables needed have been provided in models.py

From the root directory and working in your virtual environment, run the following 

```
flask db init 
flask db migrate 
flask db upgrade
```

These command will set up the defined tables in your database of choice. 

### One last thing before you run
For this project, there is encryption and decryption for which you will need to create a key.
In your terminal and in your virtual environment (your working directory should be the project root directory), open a python shell by running:

`python`

Once the python shell opens, run the following commands:
```
from main import *
write_key()

key = load_key()
f = Fernet(key)

app.app_context()_push()
user = User(username='anything_you_choose', password=f.encrypt('anything_you_choose'.encode()), department='IP', privileges='Admin')
user.insert()
```

1. `from main import *` imports everything from main.py
2. `write_key()` generates a fernet key and saves it to a file 'key.key'
3. `key = load_key(`) reads the key and saves it to the variable 'key'
4. `f = Fernet(key)` instantiates the Fernet class with the key for encryption and decryption
5. `app.app_context().push()` pushes th application context which will let you create the a user from the python shell
6. `user = User(...)` sets a User object to be added to the database
7. `user.insert()` adds and commits this user object to the database

**NOTE**: write_key() needs to only be performed once and not while you have data in the database which has been encrypted by another key.
**NOTE**: you only need to create a user from python shell to be able to get access to the database. Make sure the privileges you set for the user object is 'Admin' to be able to create more users on the platform.

## Running the Server
From the root directory of the project (and while in your virtual environment), run:

`export FLASK_APP=main.py`

If you wish to set debug to true, run:

`export FLASK_DEBUG=True`

The above commands should be run each time you open a new terminal session.

Once you've told flask where to find your application by running the commands above, then run:

`flask run`

You should now see the database app running by going [here](http://127.0.0.1/)