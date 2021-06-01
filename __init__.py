from flask import Flask

from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.secret_key = 'some secret key'

#Config SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

import routes