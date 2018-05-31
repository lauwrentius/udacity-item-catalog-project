from flask import (Flask, jsonify)
import pymysql.cursors

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db_setup import Base, Category, CategoryItem, User
import json

# EB looks for an 'application' callable by default.
application = Flask(__name__)

engine = create_engine('mysql+pymysql://lauwrentius:LAuwrent1us@aa1kczw6kaut3s5.celmatwbtx0m.us-west-2.rds.amazonaws.com/test')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

categories = session.query(Category).all()


# print a nice greeting.
def say_hello(username = "World"):
    return '<p>Hello %s!</p>\n' % username

# some bits of text for the page.
header_text = '''
    <html>\n<head> <title>EB Flask Test</title> </head>\n<body>'''
instructions = '''
    <p><em>Hint</em>: This is a RESTful web service! Append a username
    to the URL (for example: <code>/Thelonious</code>) to say hello to
    someone specific.</p>\n'''

home_link = '<p><a href="/">Back</a></p>\n'

for val in categories:
    home_link = home_link + "|" + val.name + "-"

footer_text = '</body>\n</html>'



# add a rule for the index page.
# application.add_url_rule('/', 'index', (lambda: header_text +
#     say_hello() + instructions + footer_text))
#
# # add a rule when the page is accessed with a name appended to the site
# # URL.
# application.add_url_rule('/<username>', 'hello', (lambda username:
#     header_text + say_hello(username) + home_link + footer_text))

@application.route('/')
def index():
    return 'Index Page' + home_link

# run the app.
if __name__ == "__main__":
    # Setting debug to True enables debug output. This line should be
    # removed before deploying a production app.
    application.debug = True
    application.run()
