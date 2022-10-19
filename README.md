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

## Running the Server
From the root directory of the project (and while in your virtual environment), run:

`export FLASK_APP=main.py`

If you wish to set debug to true, run:

`export FLASK_DEBUG=True`

The above commands should be run each time you open a new terminal session.

Once you've told flask where to find your application by running the commands above, then run:

`flask run`

You should now see the database app running by going [here](http://127.0.0.1/)