import re
import poplib

def get_connection(server, email_id, email_pass):
	mail_server = server
	email_connection = poplib.POP3_SSL(mail_server)

	print(email_connection.getwelcome())
	email_connection.user(email_id)
	email_connection.pass_(email_pass)

	return email_connection

def parse_email(email):
	print('---- Parsing Email ----')
	# dev
	# for i in range(0, len(email)):
		# print("LIST NO : " + str(i))
		# print(email[i].decode("utf-8"))

	response = {}
	response['status'] = True
	response['message'] = ''

	if email is None or len(email) == 0:
		response['status'] = False
		return response

	for i in range(0, len(email)):
		cleaned = email[i].decode("utf-8")
		#print(cleaned)
		pair = cleaned.split(':',1)
		if len(pair) == 2:
			response[pair[0]] = pair[1]

	if len(email) > 68:
		response['message'] = email[68].decode("utf-8")
	
	return response