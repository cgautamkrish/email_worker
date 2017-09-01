import poplib
import json
import emailUtils
import configparser
import base64
import os
import ast
import sys, getopt
from cachetools import LRUCache
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def get_salt():
	Config = configparser.ConfigParser()
	Config.read('config.ini')
	salt = Config.get('encryption','salt')
	return salt.encode()

def read_data():
	data_file = open("data", "r")
	data = data_file.read()
	data_file.close()
	return data

def initialize(password):
	# get salt from config
	salt = get_salt()
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
	key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
	f = Fernet(key)
	# read encrypted data from file
	data = read_data()
	try:
		# decrypt data into dict
		data = ast.literal_eval(f.decrypt(data.encode()).decode())
		try:
			# simple check if decryption was correct
			if data['check'] == True:
				cache_data = []
				# initialize cache to size 100 TODO: dynamic sizing
				cache = LRUCache(maxsize=100)
				for key, value in data.items():
					cache_data.append((key, value))
				# populate cache 
				cache.update(cache_data)
				print(cache)
			else:
				print('An error has occurred!')
		except Exception as e:
			print('An error has occurred!')
			print(str(e))
	except Exception as e:
		print('An error has occurred!')
		print(str(e))

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'p:')
		for o,a in opts:
			if o in ("-p", "--ppp"):
				# initial_write(a)
				initialize(a)
			else:
				sys.exit()
	except getopt.GetoptError:
		usage()
		sys.exit(2)

# FOR DEV only
def initial_write(password):
	print(password.encode())
	def save(data):
		text_file = open("data", "w")
		text_file.write(data)
		text_file.close()

	salt = b'3gft23457y0237y0327r54'
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
	key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
	f = Fernet(key)

	email_data = {}
	e = {}
	e['server'] = 'xx.xx.com'
	e['id'] = 'xx@xx.com'
	e['password'] = 'xx'
	email_data[e['id']] = e
	email_data['check'] = True

	token = f.encrypt(str(email_data).encode())
	print(token)
	save(token.decode())
	print(f.decrypt(token))

if __name__ == "__main__":
	main()