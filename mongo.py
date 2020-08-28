from flask import Flask,jsonify,request
from flask_cors import CORS,cross_origin
from flask_pymongo import PyMongo
from bson.json_util import dumps
import bcrypt
import logging
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
#from logging import FileHandler,WARNING,DEBUG,ERROR,INFO
app = Flask(__name__)
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'secret'
'''file_handler=FileHandler('errorlog.txt')
file_handler.setLevel(INFO)
app.logger.addHandler(file_handler)'''
logging.basicConfig(filename='log_flask_demo.log',level=logging.DEBUG,format = '%(asctime)s:%(levelname)s:%(message)s')
#logging.basicConfig(filename='log_flask_demo.log',level=logging.DEBUG,format = '%(asctime)s:%(levelname)s:%(message)s')
#CORS(app)
app.config["MONGO_URI"] = "mongodb://localhost:27017/usersdb"
mongo = PyMongo(app)
user_collection = mongo.db.users
role_collection = mongo.db.roles
#@cross_origin(origin='localhost',headers=['Content- Type','Authorization'])

@app.route('/add', methods=['POST'])
def add_u():
	#req_data = request.get_json()
	_data=request.json
	_name=_data['name']
	_email=_data['email']
	_role=_data["role"]
	#
	_password=_data['password']
	_password=bcrypt.hashpw(_password.encode("utf-8"),bcrypt.gensalt())
	existing=user_collection.find_one({"email":_email})
	if existing is None:
	#if _name and _email and _password and request.method=='POST':
		id=user_collection.insert({'name':_name, 'email': _email, 'role':_role,'password':_password})
		resp=jsonify("User added succesfully")
		resp.status_code=200
		return resp
	else:
		#return not_found()
		return "user already present"
@app.errorhandler(404)
def not_found(error):
	message = {
		'status':404,
		'message':'Not found'+request.url
	}
	resp=jsonify(message)
	resp.status_code=404
	return resp
@app.route('/login',methods=['POST'])
def login():
	_data=request.json
	_password=_data['password'].encode('utf-8')
	user = user_collection.find_one({"email" : _data['email']})
	database_pass=user['password']
	if user is not None :
		if bcrypt.hashpw(_password,database_pass):
			access_token = create_access_token(identity = { 'name': user['name'],'email': user['email']})
			result = jsonify({"token":access_token})
		else:
			result = jsonify({"error":"Invalid username and password"})
	else :
		result = jsonify({"result":"No results found"})
	return result 
'''	#if passs==_password:
	if bcrypt.hashpw(_password,database_pass):
	#if bcrypt.checkpw(hashed, passs): 
		return jsonify("authrorized")
	else:
		return jsonify("error")'''

@app.route('/info')
def get_all():
	users=user_collection.find()
	resp=dumps(users)
	return resp
@app.route('/addRole', methods=['POST'])
def add_roles():
	#req_data = request.get_json()
	_data=request.json
	_descrpition=_data['description']
	_role=_data["role"]
	if _descrpition and _role  and request.method=='POST':
		id=role_collection.insert({'role':_role, 'description':_descrpition})
		resp=jsonify("Role added succesfully")
		resp.status_code=200
		
		return resp
	else:
		return not_found()
@app.route('/delete/<email>',methods=['DELETE'])
def delete_user(email):
	user=user_collection.delete_one({'email':email})
	resp =jsonify("deleted succcessfully")
	resp.status_code=200
	return resp
@app.route('/update/<email>',methods=['PUT'])
def update_user(email):
	_data=request.json
	user = user_collection.find_one({"email" : _data['email']})
	
	user['name']=_data['name']
	#email=_data['email']
	user['role']=_data["role"]
	user['password']=_data['password']
	user_collection.save(user)
	resp=jsonify("User updated succesfully")
	resp.status_code=200

	#else:
	#	return not_found()
	return resp


@app.route('/')
def home_page():     
	
	#x = user_collection.find_one({'name':'Sai Praneeth Dulam'})
	#return f'<h1>User:{x["name"]}<br>E-mail:{x["email"]}</h1>'
	return "<h1>This is the homepage</h1>"


if __name__ == "__main__":
	app.run(debug=True)
'''
@app.route('/info',methods=['GET'])
def info():
	return jsonify()
@app.route('/roles',methods=["POST"])
def add_roles():
	req_data=request.get_json()
	req=req_data[0]
	role=req['role']
	descr=req["description"]
	return jsonify()

'''
