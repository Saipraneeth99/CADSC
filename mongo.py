from flask import Flask,jsonify,request,redirect, url_for, session,redirect,make_response
from flask_cors import CORS,cross_origin
from flask_pymongo import PyMongo
from bson.json_util import dumps
import bcrypt,logging
#import logging
from datetime import timedelta
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt
#from logging import FileHandler,WARNING,DEBUG,ERROR,INFO
app = Flask(__name__)
app.secret_key = "kmit123"# This will be changed
app.permanent_session_lifetime = timedelta(minutes=15)
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'secret'
logging.basicConfig(filename='log_flask_demo.log',level=logging.DEBUG,format = '%(asctime)s:%(levelname)s:%(message)s')
CORS(app)
app.config["MONGO_URI"] = "mongodb://localhost:27017/usersdb"
mongo = PyMongo(app)
user_collection = mongo.db.users
role_collection = mongo.db.roles
@cross_origin(origin='localhost',headers=['Content- Type','Authorization','Access-Control-Allow-Origin'])
#cors = CORS(app, resources={r"/api/": {"origins": ""}})

@app.route('/')
def home_page():     
	
	#x = user_collection.find_one({'name':'Sai Praneeth Dulam'})
	#return f'<h1>User:{x["name"]}<br>E-mail:{x["email"]}</h1>'
	return "<h1>This is the homepage</h1>"

@app.route('/login',methods=['POST','GET'])
def login():
	if request.method=='POST':
		_data=request.json
		_password=_data['password'].encode('utf-8')
		user_details = user_collection.find_one({"email" : _data['email']})
		database_password=user_details['password']
		if user_details is not None :
			session.permanent = True
			session["email"]=_data['email']
			if bcrypt.checkpw(_password,database_password):
				access_token = create_access_token(identity = { 'name': user['name'],'email': user['email']})
				result = jsonify({"token":access_token})
				#result = jsonify("Authorized user")
			else:
				result = jsonify({"error":"Invalid username and password"})
		else :
			result = jsonify({"result":"No results found"})
		return result 
	else:
		if "email" in session:
			return redirect(url_for('info'))#This is for super admin needs to get changed into dashboard when pages are created.
		else:
			return jsonify("Login page should be displayed")#Login page should be redirected


@app.route('/add', methods=['POST'])
def add_u():
	#req_data = request.get_json()
	_data=request.json
	_name=_data['name']
	_email=_data['email']
	_role=_data["role"]
	_password=_data['password']
	encoded_password=bcrypt.hashpw(_password.encode("utf-8"),bcrypt.gensalt())
	existing_user=user_collection.find_one({"email":_email})
	if existing_user is None:
	#if _name and _email and _password and request.method=='POST':
		id=user_collection.insert({'name':_name, 'email': _email, 'role':_role,'password':encoded_password})
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

@app.route('/info',methods=['POST'])
def get_users():
	_data=request.json()
	_email=_data["email"]
	users=user_collection.find()
	all_users=dumps(users)
	return all_users
	#return jsonify(_email)

@app.route('/deleteUser/<email>',methods=['DELETE'])
def delete_user(email):
	_data=request.json
	if _data["email"]:
		user_details=user_collection.delete_one({'email':email})
		resp =jsonify("deleted succcessfully")
		resp.status_code=200
		return resp
	else:
		resp=jsonify("Invalid input")
		#resp.status_code() need to be mentioned
	return resp

@app.route('/updateUser/<email>',methods=['PUT'])
def update_user(email):
	_data=request.json
	user_details = user_collection.find_one({"email" : _data['email']})
	
	user_details['name']=_data['name']
	#email=_data['email']
	user_details['role']=_data["role"]
	user_details['password']=_data['password']
	user_collection.save(user_details)
	resp=jsonify("User updated succesfully")
	resp.status_code=200

	#else:
	#	return not_found()
	return resp


@app.route('/addRole', methods=['POST'])
def add_roles():
	#req_data = request.get_json()
	_data=request.json
	_descrpition=_data['description']
	_role=_data["role"]
	if _descrpition and _role:#and request.method=='POST':
		id=role_collection.insert_one({'role':_role, 'description':_descrpition})
		resp=jsonify("Role added succesfully")
		resp.status_code=200
		return resp
	else:
		return not_found()
@app.route('/infoRoles',methods=['GET'])
def get_roles():
	roles=role_collection.find()
	all_roles=dumps(roles)
	return all_roles

@app.route('/updateRole',methods=['POST'])
def update_role():
	_data=request.json
	if _data["description"] and _data["role"]:
		role_details=role_collection.find_one({"role":_data['role']})
		role_details['description']=_data["description"]#role name can not be updated once created.
		role_collection.save(role_details)
		resp=jsonify("Role updated successfully")
		resp.status_code=200
	else:
		resp=jsonify("Invalid input")
		#resp.status_code() need to be mentioned
	return resp
@app.route("/logout")
def logout():
	session.pop("email", None)	
	return redirect(url_for('login'))	



if __name__ == "__main__":
	app.run(debug=True)
#just to check git
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

@app.after_request
def after_request(response):
  response.headers.add('Access-Control-Allow-Origin', '*')
  response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
  response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
  return response

'''
