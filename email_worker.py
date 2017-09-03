import poplib
import json
import emailUtils
import configparser
import base64
import os
import ast
import sys, getopt
import click
from cachetools import LRUCache
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, g
from flask import jsonify
from flask import request

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
				print("Initializing cache..")
				return cache
			else:
				print('An error has occurred!')
		except Exception as e:
			print('An error has occurred!')
			print(str(e))
	except Exception as e:
		print('An error has occurred!')
		print(str(e))

# Deprecated
def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'g:')
		for o,a in opts:
			if o in ("-g", "--ggg"):
				# initial_write(a)
				cache = initialize(a)
				return cache
			else:
				sys.exit()
	except getopt.GetoptError:
		usage()
		sys.exit(2)

# FOR DEV only
def initial_write(password, email_data):
	print(password.encode())
	def save(data):
		text_file = open("data", "w")
		text_file.write(data)
		text_file.close()

	salt = b'3gft23457y0237y0327r54'
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
	key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
	f = Fernet(key)

	token = f.encrypt(str(email_data).encode())
	print(token)
	save(token.decode())
	print(f.decrypt(token))
	return token

app = Flask(__name__)
# declare global variable for LRUCache
cache = None
pw = ''

# custom cli command to initialize email cache and starting Flask
# password to decrypt data file is cli param
@app.cli.command()
@click.option('--password', prompt='Your app password',
	help='Password')
def init(password):
	global cache
	global pw 
	cache = initialize(password)
	pw = password
	app.run()

# @app.before_first_request
# def start():
# 	cache = main()
# 	g.cache = cache

@app.route('/set')
def set():
	new_data = {}
	all_data = {}
	new_data['id'] = 1
	new_data['email_id'] = 'XX@XX.com'
	new_data['email_server'] = 'XX.XX.com'
	new_data['email_password'] = 'XX'
	all_data[new_data['email_id']] = new_data
	all_data['check'] = True
	initial_write('gautam', all_data)
	return jsonify(status="OK")

@app.route('/')
def test():
	response = "Cache is up and running"
	if cache['check'] != True:
		response = "Cache initialization failed"
	return jsonify(response=response)

@app.route('/emails', methods=['GET'])
def getAllEmails():
	print("GET all emails..")
	emails = {}
	for key in cache.keys():
		emails[key] = cache[key]
	print(emails)
	return jsonify(emails=emails)

@app.route('/email', methods =['POST'])
def updateEmailById():
	global cache
	request_body = request.get_json()
	if 'email_id' in request_body:
		try:
			email = cache[request_body['email_id']]
			return jsonify(email=email)
		except KeyError as e:
			print('Request for ' + request_body['email_id'])
	return jsonify(message='Email ID does not exist')

@app.route('/refresh')
def refreshCache():
	global cache
	global pw
	emails = {}
	cache = initialize(pw)
	for key in cache.keys():
		emails[key] = cache[key]
	return jsonify(emails=emails)
