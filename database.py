
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
my_username = "beast"
otheruser = "madhu"

mess = []
for x in messages.find({}, {"_id":0}):
    if x['from'] == my_username:
        temp = {"Right": x['Message']}
        mess.append(temp)
    else:
        temp = {"Left": x['Message']}
        mess.append(temp)

for data in mess:
    for key,value in data.items():
        if key == "Right":
            print(value)
        else:
            print(value)
        

print(len(mess))
