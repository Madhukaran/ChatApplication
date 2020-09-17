import socket
import threading
from pymongo import MongoClient
import select
import pickle
import time

client = MongoClient('mongodb://localhost:27017/')

HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 1234



server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# print(server_socket)
# seeting the option for the socket
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
	# binding the IP address t socket
	server_socket.bind((IP, PORT))
	# setting the socket for the connection
	server_socket.listen()
except Exception as e:
	raise SystemExit(f"We could not bind the server on host: {IP} to port: {PORT}, because: {e}")
# List of sockets for select.select()
sockets_list = [server_socket]
# sockets_list = []

# List of connected clients - socket as a key, user header and name as data
clients = {}
# to append the username
userName = []
# to keep the database details
databaseDict = {}

print(f'Listening for connections on {IP}:{PORT}...')

# Handles message receiving
def receive_message(client_socket):

    try:

        # Receive our "header" containing message length, it's size is defined and constant
        message_header = client_socket.recv(HEADER_LENGTH)

        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not len(message_header):
            return False

        # Convert header to int value
        message_length = int(message_header.decode('utf-8').strip())

        # Return an object of message header and message data
        return {'header': message_header, 'data': client_socket.recv(message_length)}

    except:

        # If we are here, client closed connection violently, for example by pressing ctrl+c on his script
        # or just lost his connection
        # socket.close() also invokes socket.shutdown(socket.SHUT_RDWR) what sends information about closing the socket (shutdown read/write)
        # and that's also a cause when we receive an empty message
        return False

# Handles message receiving
def receive_messageWithHeader(client_socket):

    try:

        # Receive our "header" containing message length, it's size is defined and constant
        Toheader = client_socket.recv(HEADER_LENGTH)

        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not len(Toheader):
            return False

        # Convert header to int value
        Tolength = int(Toheader.decode('utf-8').strip())
        ToMessage = client_socket.recv(Tolength)
        header = client_socket.recv(HEADER_LENGTH)
        headerLength = int(header.decode('utf-8').strip())
        messageData = client_socket.recv(headerLength)


        # Return an object of message header and message data
        return {'Toheader': Toheader, 'Todata': ToMessage,'header':header,'data':messageData}

    except:

        # If we are here, client closed connection violently, for example by pressing ctrl+c on his script
        # or just lost his connection
        # socket.close() also invokes socket.shutdown(socket.SHUT_RDWR) what sends information about closing the socket (shutdown read/write)
        # and that's also a cause when we receive an empty message
        return False

# def recevingSocket(sockets_list,clients):
# 	while True:
#
# 		read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)
#
# 		# Iterate over notified sockets
# 		for notified_socket in read_sockets:
#
# 			# If notified socket is a server socket - new connection, accept it
# 			if notified_socket != server_socket:
#
# 				# Receive message
# 				message = receive_messageWithHeader(notified_socket)
#
# 				# If False, client disconnected, cleanup
# 				if message is False:
# 					print('Closed connection from: {}'.format(clients[notified_socket]['data'].decode('utf-8')))
#
# 					# Remove from list for socket.socket()
# 					sockets_list.remove(notified_socket)
#
# 					# Remove from our list of users
# 					del clients[notified_socket]
#
# 					continue
#
# 				# Get user by notified socket, so we will know who sent the message
# 				user = clients[notified_socket]
#
# 				print(f'Received message from {user["data"].decode("utf-8")}: {message["data"].decode("utf-8")}')
#
# 				# data.insert({user["data"].decode("utf-8"):message["data"].decode("utf-8")})
# 				print(message)
#
# 				for i in databaseDict:
# 					if i == user["data"].decode('utf-8'):
# 						databs = databaseDict[i]
# 						# databs[message["Todata"].decode('utf-8')].insert_one({"message":message["data"].decode("utf-8"),"time":time.time()})
# 						databs[message["Todata"].decode('utf-8')].insert_one(
# 							{str(int(time.time())): {'message': message["data"].decode("utf-8"),'name': user["data"].decode('utf-8')}})

def on_new_client(notified_socket,userName,clients):
	# print('first thread open sucessufully')
	while True:
		# print('going to select socket')
		# read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)
		# print('select socket is completed')

		# Iterate over notified sockets
		# for notified_socket in sockets_list:
		# 	print(f'looping the socket {notified_socket}')

		# If notified socket is a server socket - new connection, accept it
		if notified_socket != server_socket:
			# print('execute else part')
			listMess = pickle.dumps(userName)
			# print('pickle file dumped')
			headerList = f"{len(listMess):<{HEADER_LENGTH}}".encode('utf-8')
			# print('pickle file header created')
			for client_socket in clients:
				# print(f'looping the scoket {client_socket}')
				# if client_socket != notified_socket:
				# print(f'sending pickle to socket {client_socket}')
				client_socket.send(headerList + listMess)
				# print(f'sended pickle file to scoket {client_socket} and the message is {headerList + listMess}')
				# Receive message
			message = receive_messageWithHeader(notified_socket)

			# If False, client disconnected, cleanup
			if message is False:
				# print('Closed connection from: {}'.format(clients[notified_socket]['data'].decode('utf-8')))

				# Remove from list for socket.socket()
				sockets_list.remove(notified_socket)

				# Remove from our list of users
				del clients[notified_socket]

				continue

			# Get user by notified socket, so we will know who sent the message
			user = clients[notified_socket]

			# print(f'Received message from {user["data"].decode("utf-8")}: {message["data"].decode("utf-8")}')

			# data.insert({user["data"].decode("utf-8"):message["data"].decode("utf-8")})
			# print(message["data"].decode("utf-8"))
			# msg = message["data"]
			# print(client_address)
			# server_socket.connect(client_address)
			# server_socket.sendto(msg,client_address)


			for i in databaseDict:
				if i == user["data"].decode('utf-8'):
					databs = databaseDict[i]
					# databs[message["Todata"].decode('utf-8')].insert_one({"message":message["data"].decode("utf-8"),"time":time.time()})
					databs[message["Todata"].decode('utf-8')].insert_one(
						{str(int(time.time())): {'message': message["data"].decode("utf-8"),
												 'name': user["data"].decode('utf-8')}})

		# threading._start_new_thread(recevingSocket, (sockets_list, clients))
	# 	msg = client.recv(1024)
	# 	if msg.decode() == 'exit':
	# 		break
	# 	print(f"The client said: {msg.decode()}")
	# 	reply = f"You told me: {msg.decode()}"
	# 	client.sendall(reply.encode('utf-8'))
	# print(f"The client from ip: {ip}, and port: {port}, has gracefully diconnected!")
	# client.close()

while True:
	try:
		read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)

		# Iterate over notified sockets
		for notified_socket in read_sockets:

			# If notified socket is a server socket - new connection, accept it
			if notified_socket == server_socket:

				# Accept new connection
				# That gives us new socket - client socket, connected to this given client only, it's unique for that client
				# The other returned object is ip/port set
				client_socket, client_address = server_socket.accept()
				# print(f'connection got from {client_address}')

				# Client should send his name right away, receive it
				user = receive_message(client_socket)
				# print(f'username got to server {user}')

				# If False - client disconnected before he sent his name
				if user is False:
					continue

				if user['data'].decode('utf-8') not in userName:
					userName.append(user['data'].decode('utf-8'))
				# Add accepted socket to select.select() list
				sockets_list.append(client_socket)

				# Also save username and username header
				clients[client_socket] = user

				# print('Accepted new connection from {}:{}, username: {}'.format(*client_address,
																				# user['data'].decode('utf-8')))
				# print(f'socket list {sockets_list}')

				threading._start_new_thread(on_new_client,(client_socket,userName,clients))
	except KeyboardInterrupt:
		print(f"Gracefully shutting down the server!")
	except Exception as e:
		print(f"Well I did not anticipate this: {e}")

server_socket.close()