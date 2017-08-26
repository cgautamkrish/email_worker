import poplib
import json
import emailUtil
import configparser

Config = configparser.ConfigParser()
Config.read('config.ini')
email_server = Config.get('email_credentials','email_server')
email_id = Config.get('email_credentials','email_id')
email_pw = Config.get('email_credentials','email_password')

email_connection = emailUtil.get_connection(email_server, email_id, email_pw)

resp, items, octets = email_connection.list()
(no_of_msgs, size) = email_connection.stat()
for i in range(1, no_of_msgs+1):
	email = email_connection.retr(i)
	parsed_email = emailUtil.parse_email(email[1])
	print(parsed_email)