
try:  
    import io
    import os
    import sys
    import  json
    import uuid
    import requests
    import jwt
    import bcrypt
    from datetime import datetime,timedelta
    from flask import Flask, request, jsonify
    from flask_cors import CORS
    from commonlib.ocrm_LoggerTool import LoggerTool
    from commonlib.ocrm_time_tool import getesttime
    from commonlib.ocrm_email_notification import EmailNotification
except Exception as e:
    print("Error occurred while importing modules " + str(e))

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),"..\\","")))
dirpath=os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
cors=CORS(app,resources={r"/dashboard/*":{"origins":"*"}})

environment="PROD"

def getConfigSettings(config_path,ENV):
    """
    Description : This function is to load config file to dict
    Args:
        config_path : config file name path
    Returns:
        config dict if succeed otherwise raise exception
    """
    environmentList = ["LOCAL", "DEV", "TST", "PROD"]
    try:
        print(ENV)
        if not ENV.upper() in environmentList:
            raise Exception("Failed to set environment variable.")

        with io.open(config_path, encoding="utf-8-sig") as outfile:
            json_object = json.loads(outfile.read())
            if(json_object != None):
                configEnv = json_object["environment"][ENV]
                return configEnv
            else:
                raise Exception(
                    "Deployment environment listed in app.cfg is either not capitalized or is incorrect")
    except Exception as e:
        print("Failed in getConfigSettings function .. " + str(e))
        raise Exception(
            "Failed in getConfigSettings function .. " + str(e))

    
def responsemessage(code,status,message):
    """This function will jsonify the response object and return to caller.

    Args:
        code (string): Error or success code
        status (string): Job status either Failed or success
        message (string): Error or success message

    Raises:
        e: Exception

    Returns:
        object: string object
    """
    try:
        return jsonify({
            "code":code,
            "status":status,
            "message":message
        })
    except Exception as e:
        print(str(e)) 


@app.errorhandler(404)
def page_not_found(e):
    "This is required when a wrong pathe is called to exit"
    print(e)
    return "<h1>404</h1><p>Requested API URL does not exist</p>",404


def get_username(email):
    """Function to extract username from email
    Args:
        email (string): email
    Returns: username
    """
    try:
        username=email.split("@")[0]
        if "." in username:
            username=username.split(".")[0]
        return username
    except Exception as e:
        print("Exception occurred while extracting username from email: "+ str(e)) 


def generate_token(username,password):
    """Function to compare passwords
    Args:
        password (string): password
        password_hash (string): hashed password
    Returns:
        Boolean: True/False
    """
    try:
        login_url = "https://www.arcgis.com/sharing/rest/generateToken"
        data = {
            "username": username,
            "password": password,
            "client": "referer",
            "referer": "https://www.arcgis.com",
            "expiration": "2",
            "f": "json"
        }
        response = requests.post(login_url, data=data)
        token_object=response.json()
        if token_object and token_object.get('error'):
            raise Exception(token_object['error']["message"])
        return token_object.get("token")

    except Exception as e:
        print("Exception occurred while decoding password: "+ str(e))
        return False         


def get_feature(table,get_token,email):
    """Function to compare passwords
    Args:
        password (string): password
        password_hash (string): hashed password
    Returns:
        Boolean: True/False
    """
    try:
        query = f"email = '{email}'"
        params = {
        "f": "json",
        "token": get_token,
        "where":query,
        "returnGeometry": True,
        "outFields": "*"
        }
        response = requests.get(table+"/query",params=params)
        return response
    except Exception as e:
        print("Exception occurred while decoding password: "+ str(e)) 
        return  False       
 

def decode_password(password,password_hash):
    """Function to compare passwords
    Args:
        password (string): password
        password_hash (string): hashed password
    Returns:
        Boolean: True/False
    """
    try:
       encodedpassword=password.encode('utf-8')
       encoded_hash_password=password_hash.encode('utf-8')
       user_status = bcrypt.checkpw(encodedpassword, encoded_hash_password)
       return user_status
    except Exception as e:
        print("Exception occurred while decoding password: "+ str(e)) 
        return  False


def encode_password(password):
    """Function to encode password
    Args:
        password (strin): password string
    returns:
        string: hashed password
    """
    try:
        hashed_input_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed_input_password.decode('utf-8')
    except Exception as e:
        print("Exception occurred while encoding password: "+ str(e)) 
 

def compare_datetime(datetime_str1,datetime_str2):
    """Function to find time difference
    Args:
        datetime_str1 (string): datetime string
        datetime_str2 (string): datetime string
    Returns:
        Double: Time difference in minuites
    """
    try:
        datetime_obj1 = datetime.strptime(datetime_str1, '%Y-%m-%d %H:%M:%S')
        datetime_obj2 = datetime.strptime(datetime_str2, '%Y-%m-%d %H:%M:%S')
        time_difference_seconds = (datetime_obj1 - datetime_obj2).total_seconds()
        time_difference_minutes = time_difference_seconds / 60
        return time_difference_minutes
    except Exception as e:
        print("Exception occurred while getting time difference: "+ str(e)) 
 
 
@app.route("/dashboard/forgot_password",methods=['POST'])
def forgot_password():
    try:
        startTime = getesttime()
        if request.method == 'POST':
            email=request.form.get("email",None)
            if len(email)<3 or '@' not in email:
                return responsemessage('e001',"Failed","Invalid input"),400            
            if email:         
                appConfig=getConfigSettings('app.cfg',environment)
                username=appConfig['username']
                password=appConfig['password']
                table=appConfig['table']
                logPath=appConfig['logFilePath']
                sender_email=appConfig['senderEmail'] 
                if not os.path.exists(logPath):
                    os.makedirs(logPath)
                logger=LoggerTool(logPath,"DASHBOARD API")

                query = f"email = '{email}'"
                get_token=generate_token(username,password)
                if not get_token:
                    return responsemessage('e001',"Failed","Registration error. Please try again later."),500    

                params = {
                    "f": "json",
                    "token": get_token,
                    "where":query,
                    "returnGeometry": True,
                    "outFields": "*"
                }
                response = requests.get(table+"/query",params=params)
                if response.status_code == 200:
                    data = response.json()
                    features = data.get("features", [])
                    if len(features)==0:
                        return responsemessage('e001',"Failed","User Not Found"),404
                    feature=features[0]["attributes"]

                    action_type=feature.get("actiontype")
                    if action_type =="inactive":
                        return responsemessage('e001',"Failed","User Not Authorized by DHEC"),401
                    if action_type =="active":
                        validation_code=str(abs(uuid.uuid4().int) % 100000).zfill(5)
                        isotime=(str(startTime))[:19]

                        update_feature_attributes = {
                        "attributes":{
                            "OBJECTID": feature["OBJECTID"],
                            "est_time": isotime,
                            "code": validation_code
                            }           
                        }
                        update_data = {
                            "updates": json.dumps([update_feature_attributes]),
                            "f": "json",
                            "token":get_token
                            }
                        response = requests.post(f"{table}/applyEdits", data=update_data)
                        if response.status_code == 200:
                                data = response.json()
                                if data["updateResults"][0]["success"]:
                                    email_notif=EmailNotification(logger)
                                    request_username=get_username(email)
                                    email_notif.send_mail(email, sender_email,validation_code,request_username)         
                                    return responsemessage('s001',"completed","Password Reset code sent to user email"),200
    except Exception as e:
        return responsemessage('e001',"Failed","Exception occcurred :"+str(e)),400       
    
     
@app.route("/dashboard/resetpassword",methods=['POST'])
def reset():
    try:
        startTime = getesttime()
        if request.method == 'POST':
            email=request.form.get("email",None)
            userpassword=request.form.get("newpassword",None)
            password_confirm=request.form.get("passwordconfirm",None)
            activation_code=request.form.get("resetcode",None)
            if userpassword!=password_confirm:
                return responsemessage('e001',"Failed","Unmatched password and password confirm"),401 
            if len(email)<3 or '@' not in email or len(userpassword)<3 or len(activation_code)<5:
                return responsemessage('e001',"Failed","Invalid input"),400            
            if email and userpassword:
                appConfig=getConfigSettings('app.cfg',environment)
                username=appConfig['username']
                password=appConfig['password']
                table=appConfig['table']
                resetcode_life=appConfig['resetcodeLife'] 
                get_token=generate_token(username,password)
                if not get_token:
                    return responsemessage('e001',"Failed","Registration error. Please try again later."),500              
                feature_response=get_feature(table,get_token,email)
                if not feature_response:
                    return responsemessage('e001',"Failed","Registration error. Please try again later."),500                   

                if feature_response.status_code == 200:
                    data = feature_response.json()
                    
                    features = data.get("features", [])
                    if len(features)==0:
                        return responsemessage('e001',"Failed","User Not Found"),404
                    
                    feature=features[0]["attributes"]
                    code=feature.get("code") 
                    reset_time=feature.get("est_time")   

                    if not code:
                        return responsemessage('e001',"Failed","Password reset not initialized"),400
                    
                    if code!=activation_code:
                        return responsemessage('e001',"Failed","Invalid Reset Code"),403
                    
                    isotime=(str(startTime))[:19]
                    time_difference=compare_datetime(isotime,reset_time)               
                    
                    if code!=activation_code:
                        return responsemessage('e001',"Failed","Invalid Reset Code"),403
    
                    if time_difference > resetcode_life:
                        return responsemessage('e001',"Failed","Expired Reset Code"),403
                    
                    passwrd=encode_password(userpassword)
                    update_feature_attributes = {
                    "attributes":{
                        "OBJECTID": feature["OBJECTID"],
                        "password": passwrd
                        }           
                    }
                    update_data = {
                        "updates": json.dumps([update_feature_attributes]),
                        "f": "json",
                        "token":get_token
                        }
                    response = requests.post(f"{table}/applyEdits", data=update_data)
                    if response.status_code == 200:
                            data = response.json()
                            if data["updateResults"][0]["success"]:
                                return jsonify({"code":"s000","message":"completed","status":"success"}),200   

            else:
                return responsemessage('e001',"Failed","Invalid email, password or resetcode"),400       
    except Exception as e:
        return responsemessage('e001',"Failed","Exception occcurred :"+str(e)),400       
        

@app.route("/dashboard/delete/<id>",methods=['DELETE'])
def delete(id):
    try:
        if request.method == 'DELETE':
            appConfig=getConfigSettings('app.cfg',environment)
            username=appConfig['username']
            password=appConfig['password']
            table=appConfig['table']
            secret_key=appConfig['secret_key']
            auth=request.headers.get("Authorization")
            if auth=='' or len(auth)<12:
                return responsemessage('e001',"Failed","Missing Authorization Token"),400    
            token=request.headers.get("Authorization").split("Bearer ")[1]
            decoded_token=jwt.decode(token,secret_key,algorithms="HS256")
            email=decoded_token["email"]
            exp=decoded_token["exp"]
            expiration_datetime=datetime.utcfromtimestamp(exp)
            if expiration_datetime < datetime.utcnow():
                return responsemessage('e001',"Failed","User Not Logged In"),401    

            get_token=generate_token(username,password)
            if not get_token:
                return responsemessage('e001',"Failed","Registration error. Please try again later."),500              
            feature_response=get_feature(table,get_token,email)
            if not feature_response:
                return responsemessage('e001',"Failed","Registration error. Please try again later."),500    
            if feature_response.status_code == 200:
                data = feature_response.json()
                
                features = data.get("features", [])
                if len(features)==0:
                     return responsemessage('e001',"Failed","You are not authorized to perform this operation."),401
                
                feature=features[0]["attributes"]
                role=feature.get("role")
                if role!="admin":
                    return responsemessage('e001',"Failed","You are not authorized to perform this operation."),401   
                add_data = {
                    "deletes": str(id),
                    "f": "json",
                    "token":get_token
                    }                    
                headers = {}
                headers["Content-Type"] = "application/json"
                response = requests.post(f"{table}/applyEdits", data=add_data)
                # Check the response
                if response.status_code == 200:
                    data = response.json()
                    if data["deleteResults"][0]["success"]:
                        return jsonify({"code":"s000","message":"completed","status":"success"}),204      
    except Exception as e:
        return responsemessage('e001',"Failed","Exception occcurred :"+str(e)),400


@app.route("/dashboard/login",methods=['POST'])
def login():
    try:
        if request.method == 'POST':
            email=request.form.get("email",None)
            userpassword=request.form.get("password",None)
            if len(email)<3 or '@' not in email or len(userpassword)<3:
                return responsemessage('e001',"Failed","Invalid input"),400
            if email and userpassword:
                appConfig=getConfigSettings('app.cfg',environment)
                username=appConfig['username']
                password=appConfig['password']
                table=appConfig['table']
                secret_key=appConfig['secret_key']
                query = f"email = '{email}'"
                get_token=generate_token(username,password)
                if not get_token:
                    return responsemessage('e001',"Failed","Registration error. Please try again later."),500    

                params = {
                "f": "json",
                "token": get_token,
                "where":query,
                "returnGeometry": True,
                "outFields": "*"
                }
                response = requests.get(table+"/query",params=params)
                if response.status_code == 200:
                    data = response.json()
                    features = data.get("features", [])
                    if len(features)==0:
                        return responsemessage('e001',"Failed","User Not Found"),404
                    feature=features[0]["attributes"]
                    hashed_password=feature.get("password")
                    phone=feature.get("phone")
                    action_type=feature.get("actiontype")
                    if action_type.lower()=="active":
                        status=decode_password(userpassword,hashed_password)
                        if not status:
                            return responsemessage('e001',"Failed","Invalid username or password."),403
                        payload = {
                            "email": email,
                            "phone": phone,
                            "exp": datetime.utcnow() + timedelta(hours=1)  
                        }
                        token = jwt.encode(payload, secret_key, algorithm="HS256")
                        return jsonify({"code":"s000","message":"completed","status":"success","token":token}),200  
                    else:
                        return responsemessage('e001',"Failed","Contact DHEC OCRM staff to get authorized."),400    
            else:
                return responsemessage('e001',"Failed","Invalid email,phone or password"),400           
    except Exception as e:
        return responsemessage('e001',"Failed","Exception occcurred :"+str(e)),400


@app.route("/dashboard/register",methods=['POST'])
def register():
    try:
        if request.method == 'POST':
            email=request.form.get("email",None)
            userpassword=request.form.get("password",None)
            password_confirm=request.form.get("passwordconfirm",None)
            organization=request.form.get("organization",None)
            position=request.form.get("position_in_org",None)
            phone=request.form.get("phone",None)
            if userpassword!=password_confirm:
                return responsemessage('e001',"Failed","Unmatched password and password confirm"),401 
            if len(email)<3 or '@' not in email or len(userpassword)<3 or len(phone)<3:
                return responsemessage('e001',"Failed","Invalid input"),400
            if len(position)<3 or len(organization)<3:
                return responsemessage('e001',"Failed","Invalid input : Organization or Position should not be less than 3 characters"),400            
            if email and userpassword and phone:
                appConfig=getConfigSettings('app.cfg',environment)
                username=appConfig['username']
                password=appConfig['password']
                table=appConfig['table'] 

                get_token=generate_token(username,password)
                if not get_token:
                    return responsemessage('e001',"Failed","Registration error. Please try again later."),500    

                feature_response=get_feature(table,get_token,email)
                if not feature_response:
                    return responsemessage('e001',"Failed","Registration error. Please try again later."),500    
                if feature_response.status_code == 200:
                    data = feature_response.json()
                    features = data.get("features", [])
                    if len(features)>0:
                        return responsemessage('e001',"Failed","User already exist"),409
                    passwrd=encode_password(userpassword)
                    new_feature_attributes = {
                    "attributes":{
                        "email": email,
                        "password": passwrd,
                        "phone": phone,
                        "organization":organization,
                        "position_in_org":position
                        }           
                    }
                    add_data = {
                        "adds": json.dumps([new_feature_attributes]),
                        "f": "json",
                        "token":get_token
                        }
                    headers = {}
                    headers["Content-Type"] = "application/json"
                    response = requests.post(f"{table}/applyEdits", data=add_data)
                    # Check the response
                    if response.status_code == 200:
                        data = response.json()
                        if data["addResults"][0]["success"]:
                            return jsonify({"code":"s000","message":"completed","status":"success"}),201 
            else:
                return responsemessage('e001',"Failed","Invalid email,phone or password"),400           
    except Exception as e:
        return responsemessage('e001',"Failed","Exception occcurred :"+str(e)),400


@app.route("/dashboard",methods=['GET'])
def mytest():
    try:        
        return responsemessage('s001',"completed","Test successfull"),200
    except Exception as e:
        return responsemessage('e001',"Failed","Exception occcurred :"+str(e)),400     

if __name__=="__main__":
    # app.run(debug=True)
    app.run()