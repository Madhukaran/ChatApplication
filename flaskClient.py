from flask import Flask,request,jsonify,render_template,redirect,url_for
import socket
from pymongo import MongoClient
import bcrypt
from flask_restful import reqparse
import pickle
import select
import errno


# from mess import *



app = Flask(__name__)
parser = reqparse.RequestParser()

my_username = 'ChatAPP'

client = MongoClient('mongodb://localhost:27017/')
db = client.loginDetail
data = db['loginCredential']
message = db['messages']

def checkUserExist(username):
    if data.find({"username":username}).count() > 0:
        return True
    else:
        return False

def checkUserPass(username,password):
    hashed_pw = data.find({"username":username})[0]["password"]
    if bcrypt.hashpw(password.encode('utf-8'),hashed_pw) == hashed_pw:
        return True
    else:
        return False

@app.route('/')
def firstPageFun():
    return render_template('login.html')

@app.route('/', methods=['POST'])
def newFunc():
    print('post of the login page is executed')
    # getting the input
    username = request.form['username']
    passw = request.form['password']
    print(username)
    print(passw)
    global my_username
    # checking the user already exist or not
    if checkUserExist(username):
        print(checkUserExist(username))
        # checking the password is correct or not
        if checkUserPass(username,passw):
            print(checkUserPass(username,passw))
            # encoding the username to send
            my_username = username
            username = my_username.encode('utf-8')
            username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
            # sending the username in bytes format
            client_socket.send(username_header + username)
            print(' userName sended to server ')
            return redirect(url_for('mainChatPage'))
        else:
            errno = 'Invalid username or Password. Check Your username and password'
            return render_template('login.html', erro = errno)
    else:
        errno = 'Invalid username or Password. Check Your username and password'
        return render_template('login.html', erro=errno)


#
@app.route('/signUp')
def signUp():
    return render_template('signup.html')
#
@app.route('/signUp',methods=['POST'])
def signUpPost():
    print('post method of sign up is executed')
    username = request.form['username']
    passw = request.form['password']
    print(username)
    print(passw)
    # checking the user is already exist or not
    if not checkUserExist(username):
        # encrypting the password
        hashedpw = bcrypt.hashpw(passw.encode('utf-8'),bcrypt.gensalt())
        # inserting the username and the encrypted password in the database
        data.insert({'username':username,'password':hashedpw})
        return redirect(url_for('firstPageFun'))
    else:
        return render_template('signUp.html',errno='Enter username already exist. Try different user name')

#sending message from the user to the other user
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

# update the dynamic tables
@app.route('/_update', methods = ['GET'])
def update():
    mess = []
    for x in message.find({}, {"_id":0}):
        mess.append(x)

    return jsonify(pack = mess[-1])

@app.route('/mainChatPage', methods=['GET','POST'])
def mainChatPage():
    print('the main page endpoint executed')
    parser.add_argument("Toname", help="id is requied", required=False)
    parser.add_argument("message", help="message is required", required=False)
    parsed_data = parser.parse_args()
    otherUser = parsed_data['Toname']
    sendingMessage = parsed_data['message']
    print(f' the recevied other username {otherUser} and the message {sendingMessage}')
    
    #sending message to the user
    sendMessage(otherUser, sendingMessage)

    #Storing Messages
    if otherUser == None or sendingMessage == None:
        print("dumping nonetype values")
    else:
        message.insert({'from':my_username, 'To':otherUser, 'Message':sendingMessage})
        print("message inserted")

    #retrieving messages
    for fetch in message.find():
        get = fetch



    # Receive our "header" containing pickle length, it's size is defined and constant
    pickleHeader = client_socket.recv(HEADER_LENGTH)
    print(f'recevied pickle header value {pickleHeader}')
    # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
    if not len(pickleHeader):
        print('Connection closed by the server')
        return 'Connection closed by the server'

    # Convert header to int value
    pickleLength = int(pickleHeader.decode('utf-8').strip())

    # Receive pickle file
    pickleFile = client_socket.recv(pickleLength)
    print(f'recevied pickle file {pickleFile}')
    #load the pickle file
    connectionList = pickle.loads(pickleFile)
    print('pickle is loaded')
    # removing the current user name
    connectionList.remove(my_username)
    mess = {}
    print('retriving data from mongodb')
    if otherUser != None:
        print("test:Usercheck")
        # retriving the user and the sender data and sorting based on the time and updating the one dictionary
        for i, j in zip(client[my_username][otherUser].find({}, {'_id': 0}),client[otherUser][my_username].find({}, {'_id': 0})):
            print('retrived data')
            mess.update(j)
            mess.update(i)
        print(mess)
        mess = dict(sorted(mess.items(), key=lambda t: t[0]))

        print(f'the connection list {connectionList}')
    
        
    print('executing the main page html')
    return render_template("testing_chat_module.html",tag = connectionList,message = get,username = my_username,otherUser = otherUser)



if __name__ == "__main__":
    HEADER_LENGTH = 10

    IP = "127.0.0.1"
    PORT = 1234


    # Create a socket
    # socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
    # socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to a given ip and port
    client_socket.connect((IP, PORT))
    # getting the input port number
    client_port=input("enter the client port(above 1200):-")
    app.run(port=client_port)