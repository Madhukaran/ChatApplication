# library class file for the other sending and receiving of the messages due to highly confused.
# scripted on - 14/09/2020 {BEAST}
# just for refrence its not imported to either Client or Server

from flask import Flask,request,jsonify,render_template,redirect,url_for
import socket
from pymongo import MongoClient
import bcrypt
from flask_restful import reqparse
import pickle
import select
import errno



def sendMessage(otherUser,sendingMessage):
    HEADER_LENGTH = 10
    Tomessage, message = otherUser, sendingMessage
    if Tomessage == None or message == None:
        print("Dumping None values")
    else:    
        to = Tomessage.encode('utf-8')
        encM = message.encode('utf-8')
        hdr = f"{len(to):<{HEADER_LENGTH}}".encode('utf-8')
        messh = f"{len(encM):<{HEADER_LENGTH}}".encode('utf-8')
        client_socket.send(hdr + to + messh + encM)
        print("message sent")