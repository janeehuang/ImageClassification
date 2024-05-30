from flask import Flask, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import numpy as np
import requests

from keras.applications import InceptionV3
from keras.applications.inception_v3 import preprocess_input
from keras.applications import imagenet_utils
from tensorflow.keras.preprocessing.image import img_to_array
from PIL import Image
from io import BytesIO

app = Flask(__name__)
api = Api(app)

pretrained_model = InceptionV3(weights="imagenet")

client = MongoClient("mongodb://db:27017")

db = client.ImageRecongnition
users = db["users"]

def userExist(username):
    if users.count_documents({"username":username}) == 0:
        return False
    else:
        return True

class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        if userExist(username):
            retJson = {
                "status" : 301,
                "msg" : "Invalid username, user already exist."
            }
            return retJson
            

        hashed_pw = bcrypt.hashpw(password.encode("utf8"),bcrypt.gensalt())

        users.insert_one({
            "username" : username,
            "password" : hashed_pw,
            "tokens" : 6
        })

        retJson = {
            "status" : 200,
            "msg" : "You've register successfully."
        }

        return retJson

def verify_pw(username, password):
    if not userExist(username):
        return False
    
    hashed_pw = users.find({
        "username" : username
    })[0]["password"]
        
    if bcrypt.hashpw(password.encode("utf8"),hashed_pw) == hashed_pw:
        return True
    else:
        return False


def verify_credentials(username, password):
    if not userExist(username):
        return generate_return_dictionary("301","Invalid username"), True

    correct_pw = verify_pw(username, password)

    if not correct_pw:
        return generate_return_dictionary("302","Invalid password"), True

    return None, False





def generate_return_dictionary(status, msg):
    retJson = {
        "status" : status,
        "msg" : msg
    }
    return retJson

class Classify(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        url = postedData["url"]

        retJson, error = verify_credentials(username, password)
        if error:
            return retJson
        
        tokens = users.find({
            "username" : username
        })[0]["tokens"]

        if tokens <= 0:
            return generate_return_dictionary(303,"Not Enough Tokens")
        
        if not url:
            return ({"error" : "No url provided."}),400
        
        response = requests.get(url)
        img = Image.open(BytesIO(response.content))

        img = img.resize((299,299))
        img_array = img_to_array(img)
        img_array = np.expand_dims(img_array, axis = 0)
        img_array = preprocess_input(img_array)

        prediction = pretrained_model.predict(img_array)
        actual_prediction = imagenet_utils.decode_predictions(prediction, top = 5)

        retJson = {}
        for pred in actual_prediction[0]:
            retJson[pred[1]] = float(pred[2]*100)
        
        users.update_one({
            "username": username
        },{
            "$set":{
                "tokens" : tokens - 1
            }
        })

        return retJson

class Refill(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["admin_pw"]
        amount = postedData["amount"]

        if not userExist(username):
            return generate_return_dictionary("301","Invalid username")
        
        correct_pw = "123xyz"
        if not password ==correct_pw:
            return generate_return_dictionary("302", "Incorrect Password")
        

        users.update_one({
            "username" : username
        },{
        "$set":
        {"tokens": amount}}
        )

        return generate_return_dictionary("200","Refill successfully")


api.add_resource(Register, "/register")
api.add_resource(Classify, "/classify")
api.add_resource(Refill, "/refill")

if __name__ == "__main__":
    app.run(host = "0.0.0.0")