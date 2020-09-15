from flask import Flask, render_template, request, jsonify
from flask_restful import Resource, reqparse
import random


app = Flask(__name__)


parser = reqparse.RequestParser()

@app.route('/_update')
def _update():
   
   username1=["madhu","sheik","hema","ramya","sriram","mohan","dhana","akshaya","beast1","beast2","beast3","beast4","beast5","beast6","beast7","beast8","beast9"]
   messages1=["hi","hello","how are you", "fine"]
   list_ = random.sample(username1, 5)

   return jsonify(user = list_, msg = messages1)




@app.route('/',methods=['GET','POST'])
def index():
   # this complete file is just for module testing purpose.. dont confuse with actual code
   # after sucessfull tesing module copy code and paste and use it on project
   
   parser.add_argument("Toname", help="id is requied", required=False)
   parser.add_argument("message", help="name is required", required=False)

   username=["madhu","sheik","hema","ramya","sriram","mohan","dhana","akshaya","beast1","beast2","beast3","beast4","beast5","beast6","beast7","beast8","beast9"]
   messages=["hi","hello","how are you", "fine"]

   parsed_data = parser.parse_args()
   print(parsed_data)

   return render_template("testing_chat_module.html", len=len(username),tag = username, message= messages)

if __name__ == '__main__':
   app.run(debug = True)