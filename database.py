
from flask import Flask, jsonify, render_template, request
import webbrowser
import time
from pymongo import MongoClient
import random

# app = Flask(__name__)

client = MongoClient('mongodb://localhost:27017/')
db = client.loginDetail
data = db['loginCredential']
messages = db['messages']

# @app.route('/')
# def index():
#     fetch = 
#     return render_template('sample.html')

    
# if __name__ == '__main__':
#     app.run()

mess = []
for x in messages.find({}, {"_id":0}):
    mess.append(x)

print(mess[0]['Message'])
