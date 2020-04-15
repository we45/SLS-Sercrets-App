import boto3
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, jsonify
import base64
import jwt
import os
from boto3.dynamodb.conditions import Key
import json

kms_cmk = os.environ.get('KEY_ID')
db = 'envelope-tables'
BLOCK_SIZE = 16

dynamo = boto3.resource('dynamodb')
ssm = boto3.client('ssm', region_name='us-west-2')
client = boto3.client('kms')

jwt_pwd = ssm.get_parameter(Name = 'we45-sls-jwt-pass', WithDecryption = True)['Parameter']['Value']

app = Flask(__name__)

def gen_key_seed():
    data_key = client.generate_data_key(
        KeyId=kms_cmk,
        KeySpec="AES_256",
    )
    ciphertext_blob = base64.b64encode(data_key.get('CiphertextBlob')).decode()
    plaintext_key = data_key.get('Plaintext')
    return ciphertext_blob, plaintext_key

def encrypt( enc_key,raw ):
    raw = pad(raw,BLOCK_SIZE)
    iv = Random.new().read( AES.block_size )
    cipher = AES.new( enc_key, AES.MODE_CFB, iv )
    return str(base64.b64encode( iv + cipher.encrypt( raw ) ),'utf-8' )

def decrypt( enc_key, enc ):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(enc_key, AES.MODE_CFB, iv )
    return str(unpad(cipher.decrypt( enc[16:] ), BLOCK_SIZE),'utf-8')

def validate_user(token):
    try:
        decoded = jwt.decode(token, jwt_pwd, algorithms=['HS256'])
        if 'email' in decoded:
            table = dynamo.Table(db)
            response = table.query(
                KeyConditionExpression=Key('email').eq(decoded['email'])
            )
            resp_email = response.get('Items')[0].get('email')
            if resp_email:
                return True
            else:
                return False
        else:
            seclog('validated_user: Token validation failed')
            return False
    except jwt.DecodeError:
        print("validate_user: unable to verify user using JWT")
        return False
    except jwt.InvalidSignatureError:
        j_dec = json.dumps(jwt.decode(token, verify=False))
        print("validate_user: Invalid JWT signature {}".format(j_dec))
        return False
            


@app.route('/signup',methods = ['POST'])
def create_user():
    jbody = request.json
    if isinstance(jbody, dict):
        if 'email' in jbody and 'password' in jbody:
            print(jbody)
            table = dynamo.Table(db)
            response = table.query(
                KeyConditionExpression=Key('email').eq(jbody['email'])
            )
            if response.get('Items'):
                return jsonify({"error":"user with this email already exists"}), 400            
            key, plaintext_key = gen_key_seed()
            password = jbody['password']
            password = encrypt(plaintext_key,password.encode())
            table.put_item(
                Item={
                    'email': jbody['email'],
                    'key': key,
                    'password':password
                }
            )
            return {"success": "created user: {}".format(jbody['email'])}
        else:
            return jsonify({"error":"bad request"}), 400
    else:
        return jsonify({"error":"bad request"}), 400


@app.route('/login',methods = ['POST'])
def login():
    jbody = request.json
    if isinstance(jbody, dict):
        if 'email' in jbody and 'password' in jbody:
            table = dynamo.Table(db)
            response = table.query(
                KeyConditionExpression=Key('email').eq(jbody['email'])
            )
            if response.get('Items'):
                key = response.get('Items')[0].get('key')
                password = response.get('Items')[0].get('password')
                data_key_encrypted = base64.b64decode(key)
                response = client.decrypt(CiphertextBlob=data_key_encrypted)
                key = response.get('Plaintext')
                plaintext = decrypt(key,password)
                if plaintext == jbody['password']:
                    token = jwt.encode({'email': jbody['email']}, jwt_pwd, algorithm='HS256')                             
                    return jsonify({"token": token.decode()}), 200
                else:
                    return jsonify({"error": "password mismatch"}), 403
            else:
                return jsonify({"error": "no record found"}), 404
        else:
            return jsonify({"error":"bad request"}), 400
    else:
        return jsonify({"error":"bad request"}), 400


@app.route('/create-card', methods=['POST'])
def create_card():
    if 'Authorization' in request.headers:
        jbody = request.json
        if validate_user(request.headers.get('Authorization')):
            token = request.headers.get('Authorization')
            print(token)
            decoded = jwt.decode(token, jwt_pwd, algorithms=['HS256'])
            if request.method == 'POST':
                if isinstance(jbody, dict):
                    if 'ccn' in jbody:
                        ccn = jbody.get('ccn')
                        table = dynamo.Table(db)
                        response = table.query(
                            KeyConditionExpression=Key('email').eq(decoded.get('email'))
                        )
                        if response.get('Items'):
                            password = response.get('Items')[0].get('password')
                            enc_key = response.get('Items')[0].get('key')
                            data_key_encrypted = base64.b64decode(enc_key)
                            response = client.decrypt(CiphertextBlob=data_key_encrypted)
                            enc_key = response.get('Plaintext')

                            enc_ccn = encrypt(enc_key,ccn.encode())
                            response = table.update_item(
                                Key={
                                'email': decoded.get('email'),
                                'password': password
                                },
                                UpdateExpression="set ccn = :r",
                                ExpressionAttributeValues={
                                    ':r': enc_ccn,
                                    },
                                ReturnValues="UPDATED_NEW"
                                )
                            return jsonify({"success": "new card created"}), 201
                    else:
                        return jsonify({'error': 'card number needs to be present'}), 400
                    return jsonify({"success": "new card created"}), 201
                else:
                    return jsonify({"error": "Invalid request"}), 403
            else:
                return jsonify({"error": "Invalid method. Try POST"}), 403
        else:
            return jsonify({"error": "Invalid User"}), 403
    else:
        return jsonify({"error": "No Authorization token"}), 403


@app.route('/get-card', methods=['GET'])
def get_card():
    if 'Authorization' in request.headers:
        if validate_user(request.headers.get('Authorization')):
            token = request.headers.get('Authorization')
            if request.method == "GET":
                decoded = jwt.decode(token, jwt_pwd, algorithms=['HS256'])
                table = dynamo.Table(db)
                response = table.query(
                    KeyConditionExpression=Key('email').eq(decoded.get('email'))
                )
                if response.get('Items'):
                    enc_ccn = response.get('Items')[0].get('ccn')
                    enc_key = response.get('Items')[0].get('key')
                    data_key_encrypted = base64.b64decode(enc_key)
                    response = client.decrypt(CiphertextBlob=data_key_encrypted)
                    enc_key = response.get('Plaintext')
                    ccn = decrypt(enc_key, enc_ccn)
                    return jsonify({"email": decoded.get('email'), "ccn": ccn}), 200
                else:
                    return jsonify({"error": "no record found"}), 404
            else:
                return jsonify({"error": "Invalid method. Try GET"}), 403
        else:
            return jsonify({"error": "Invalid User"}), 403
    else:
        return jsonify({"error": "No Authorization token"}), 403


# app.run(debug=True)

