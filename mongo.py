from flask import Flask,jsonify,request,redirect, url_for, session,redirect,make_response
from flask_cors import CORS,cross_origin
from flask_pymongo import PyMongo
from bson.json_util import dumps
from bson.objectid import ObjectId
import bcrypt,logging,datetime
from logging.handlers import TimedRotatingFileHandler
from datetime import timedelta
import json
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt
import secrets
app = Flask(__name__)
#app.secret_key = "kmit123"# This will be changed
#app.config['CORS_HEADERS'] = 'Content-Type'
app.permanent_session_lifetime = timedelta(minutes=15)
#jwt = JWTManager(app)
#app.config['JWT_SECRET_KEY'] = 'secret' "logs/{:%H-%M}.log".format(datetime.datetime.now())
app.config['SECRET_KEY'] = 'secret'
#logging.handlers.TimedRotatingFileHandler(filename='CADSClogs/CADSC{:%Y-%m-%d}.log'.format(datetime.datetime.now()), when='d', interval=1)#, backupCount=0, encoding=None, delay=False, utc=False, atTime=None)
#logging.basicConfig(filename='log_flask_demo.log',level=logging.DEBUG,format = '%(asctime)s:%(levelname)s:%(message)s')
logging.basicConfig(filename='CADSClogs/CADSC_{:%Y-%m-%d}.log'.format(datetime.datetime.now()),level=logging.INFO,format = '%(asctime)s:%(levelname)s:%(message)s')
#CORS(app)
#CORS(app, support_credentials=True)
#CORS(app, resources=r'/*')
#cors = CORS(app, resources={r"/*": {"origins": "http://localhost:port"}},allow_headers={*})
app.config["MONGO_URI"] = "mongodb://localhost:27017/usersdb"
mongo = PyMongo(app)
user_collection = mongo.db.users
role_collection = mongo.db.roles
session_collection=mongo.db.session
#@cross_origin(origin='localhost',headers=['Content- Type','Authorization','Access-Control-Allow-Origin'])
#@cross_origin(origin='localhost',allow_headers)
#@cross_origin(origin='localhost',headers=['Content- Type','Authorization'])
cors = CORS(app, resources={r"/*": {"origins": "*"}})
app.config['SECRET_KEY'] = 'abcdefgh'
app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=30)
@app.route('/')
def home_page():     
	
	#x = user_collection.find_one({'name':'Sai Praneeth Dulam'})
	#return f'<h1>User:{x["name"]}<br>E-mail:{x["email"]}</h1>'
	return "<h1>This is the homepage</h1>"

@app.route('/login',methods=['POST','GET'])
def login():
	if request.method=='POST':
		_data=request.json
		logging.info(_data)
		_password=_data['password'].encode('utf-8')
		user_details = user_collection.find_one({"email" : _data['email']})
		database_password=user_details['password']
		if user_details is not None :
			if bcrypt.checkpw(_password,database_password):
				session.permanent = True
				_token=secrets.token_urlsafe()
				session["token"]=_token
				valid_from=datetime.datetime.now()#created_time
				session_collection.insert_one({'token':_token,'start_time':valid_from,'end_time':valid_from+datetime.timedelta(minutes=30)})
				logging.info(session["token"])
				#access_token = create_access_token(identity = { 'name': user['name'],'email': user['email']})
				#session=eyJfcGVybWFuZW50Ijp0cnVlLCJlbWFpbCI6InRlc3QzQGdtYWlsLmNvbSJ9.X1CPxA.MD8g6c-nrJE7MulaJ5j_haxNDCU; Expires=Thu, 03-Sep-2020 06:55:04 GMT; HttpOnly; Path=/
				#result = jsonify({"token":access_token})
				
				#result=jsonify({"status":"300","token":_token})
				result=jsonify({"status":"300","token":_token})
				logging.info('User %s logged in'%_data["email"])
				#result.status_code(200)#success
				#result = jsonify("Authorized user")
			else:
				#result = jsonify({"error":"Invalid username and password"})
				#result.status_code(101)#invalid credentials
				result=jsonify({"status":"101"})
		else :
			#result = jsonify({"result":"No results found"})
			#result.status_code(102)#Not found in database
			result=jsonify({"status":"102"})
		return result 
	else:
		if "token" in session:
			return jsonify("it is there")#redirect(url_for('info'))#This is for super admin needs to get changed into dashboard when pages are created.
		else:
			return jsonify({"status":"600"})#Login page should be redirected, Not authorized


@app.route('/add', methods=['POST'])
def add_u():
	#req_data = request.get_json()
	_data=request.get_json()
	#temp=request.get()
	#logging.info(temp)
	_name=_data["name"]
	_email=_data['email']
	_role=_data["roles"]
	_password=_data['password']
	#logging.info(_role)
	if _name and _email and _password:#_role and 
		encoded_password=bcrypt.hashpw(_password.encode("utf-8"),bcrypt.gensalt())
		existing_user=user_collection.find_one({"email":_email})
		_new_role=[]
		for i in _role:
		# 	
			logging.info(i)
			temp=i["$oid"]
			role_details=role_collection.find_one({"_id": ObjectId(temp)})
			_new_role.append(role_details.get('_id'))
		# 	 logging.info(_new_role)
		
		if existing_user is None:
		#if _name and _email and _password and request.method=='POST':
			id=user_collection.insert_one({'name':_name, 'email': _email,'password':encoded_password ,'role':_new_role})
			#id=user_collection.insert_one({'name':_name, 'email': _email,'password':encoded_password})
			#resp=jsonify("User added succesfully")
			resp=jsonify({"status":"300"})
			logging.info('User %s is added'%_name)
			
		else:
			#return not_found()
			resp=jsonify({"status":"103"}) #Email present , can not add this email
		return resp
	else:
		resp=jsonify({"status":"105"})#Missing email
		return resp
	
		
	'''
		
@app.errorhandler(404)
def not_found(error):
	message = {
		'status_code':404,
		'message':'Not found'+request.url
	}
	resp=jsonify(message)
	resp.status_code=404
	return resp'''
@app.route('/infoR',methods=['POST'])
def get_role():
	_data=request.get_json()
	#logging.info(_data)
	_role=_data["roles"]
	_new_role=[]
	for i in _role:
		temp=i["$oid"]
		role_details=role_collection.find_one({"_id": ObjectId(temp)})
		_new_role.append(role_details)
	all_roles=dumps(_new_role)
	return all_roles
	
@app.route('/info',methods=['GET'])
def get_users():
	#_data=request.json
	#_email=_data["email"]
	_token=request.headers['authorization']
	session_details=session_collection.find_one({"token":_token}) 
	#if session_details and _token in session['token']:
	#if session_details is session['token']:
	logging.info(_token)
	users=user_collection.find()
	
	all_users=dumps(users)
	#all_users=json.loads(all_users)
	#logging.info(type(all_users))
	#all_users.join({"status":"308"})
	#all_users.append({"status":"308"})
	#resp=jsonify({"status":"108"})
	return all_users 
	

@app.route('/deleteUser',methods=['DELETE'])
def delete_user():
	_token=request.headers['authorization']
	session_details=session_collection.find_one({"token":_token}) 
	#if session_details and _token in session['token']:
	if session_details is session['token']:
		_data=request.json
		_email=_data["email"]
		if _email:
			user_details=user_collection.delete_one({'email':_email})
			resp =jsonify({"status":"301"}) # Deleted user successfully
			#resp.status_code=200
			logging.info("User %s Deleted Successfully"%_email)
			return resp
		else:
			resp=jsonify({"status":"106"})#email expected
			#resp.status_code() need to be mentioned
		return resp

@app.route('/updateUser',methods=['POST'])
def update_user():
	_data=request.json
	logging.info(_data)
	_email=_data['email']
	if _email:
		user_details = user_collection.find_one({"email" : _email})
		
		user_details['name']=_data['name']
		#email=_data['email']
		_role=_data["roles"]
		#encoded_password=bcrypt.hashpw(_data['password'].encode("utf-8"),bcrypt.gensalt())
		#user_details['password']=encoded_password
		_new_role=[]
		for i in _role:
			temp=i["$oid"]
			role_details=role_collection.find_one({"_id": ObjectId(temp)})
			_new_role.append(role_details.get('_id'))
			#_new_role.append(role_details.get('_id'))

		user_details['role']=_new_role
		user_collection.save(user_details)
		resp=jsonify({"status":"302"})#user updated
		logging.info("User %s Updated Successfully"%_email)
		#else:
		#	return not_found()
	else:
		resp=jsonify({"status":"106"})#email expected
	return resp


@app.route('/addRole', methods=['POST'])
def add_roles():
	_token=request.headers['authorization']
	session_details=session_collection.find_one({"token":_token})
	if session_details:
	#req_data = request.get_json()
		_data=request.json
		_descrpition=_data['description']
		_role=_data["role"]
		if _descrpition and _role:#and request.method=='POST':
			id=role_collection.insert_one({'role':_role, 'description':_descrpition})
			resp=jsonify({"status":"300"})#adding role successfully
		else:
			resp=jsonify({"status":"104"})
		#return resp
	else:
		resp=jsonify({"status":"602"})
	return resp
@app.route('/infoRoles',methods=['GET'])
def get_roles():
	_token=request.headers['authorization']
	session_details=session_collection.find_one({"token":_token})
	#if session_details:
	roles=role_collection.find()
	all_roles=dumps(roles)
	return all_roles
	# else:
	# 	resp=jsonify({"status":"602"})
	# return resp

@app.route('/updateRole',methods=['POST'])
def update_role():
	_token=request.headers['authorization']
	session_details=session_collection.find_one({"token":_token})
	if session_details:
		_data=request.json
		role_details=role_collection.find_one({"role":_data['role']})
		#if _data["description"] and _data["role"]:
		if role_details:
			role_details['description']=_data["description"]#role name can not be updated once created.
			role_collection.save(role_details)
			resp=jsonify({"status":"305"})#updationof role
		else:
			resp=jsonify({"status":"106"})#irole not found in database
			#resp.status_code() need to be mentioned
		return resp
	else:
		resp=jsonify({"status":"602"})
	return resp

@app.route('/deleteRole',methods=['POST'])
def delete_role():
	_data=request.json
	_role=_data["role"]
	role_details=role_collection.find_one({"role":_role})
	if _data["role"] and role_details:
		existing_role=user_collection.find_one({'role':data['role']})
		if existing_role:
			logging.info("Tried deleting %s"%_data["role"])
			resp=jsonify("Role assigned to more than one user, Role deletion not possible")
			#resp.status_code=
		else:
			role_collection.delete_one({'role':role_details})
			resp=jsonify({"status":"306"})
			#resp.status_code=
	else:
		resp=jsonify({"status":"107"})
		#resp.status_code=
	return resp


@app.route("/signouts")
def logout():
	_token=request.headers['token']
	session.pop("token", None)	
	session_details=session_collection.find_one({"token":_token})
	session_collection.delete_one(session_details)
	logging.info(session)
	resp=jsonify({"status":"601"})
	#return redirect(url_for('login'))	
	return resp



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
--
 res = make_response(jsonify({"message": "OK"}), 200)

    return res

@app.after_request
def after_request(response):
  response.headers.add('Access-Control-Allow-Origin', '*')
  response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
  response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
  return response

'''
