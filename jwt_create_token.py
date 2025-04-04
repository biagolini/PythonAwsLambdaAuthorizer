import json
import boto3
import jwt
import os
import bcrypt
import time

# AWS resource clients
dynamodb = boto3.resource('dynamodb')
credentials_table = dynamodb.Table(os.environ['CREDENTIALS_TABLE_NAME'])
jwt_secret = os.environ['JWT_SECRET']

# Common HTTP response headers
RESPONSE_HEADERS = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
    'Access-Control-Allow-Methods': 'OPTIONS, GET'
}

def lambda_handler(event, context):
    try:
        user_identifier = event.get('user_id')
        password = event.get('password')

        if not user_identifier or not password:
            return {
                'statusCode': 400,
                'headers': RESPONSE_HEADERS,
                'body': json.dumps({'message': 'Missing user_id or password'})
            }

        response = credentials_table.get_item(Key={'user_id': user_identifier})
        user_record = response.get('Item')

        if not user_record or not user_record.get('passwordHash'):
            return {
                'statusCode': 401,
                'headers': RESPONSE_HEADERS,
                'body': json.dumps({'message': 'Invalid user identifier or credentials'})
            }

        stored_password_hash = user_record['passwordHash']

        # Password verification using bcrypt
        if not bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
            return {
                'statusCode': 401,
                'headers': RESPONSE_HEADERS,
                'body': json.dumps({'message': 'Invalid user identifier or credentials'})
            }

        # JWT token generation
        token_payload = {
            'user_id': user_identifier,
            'exp': int(time.time()) + 604800  # Token expires in 1 week
        }
        jwt_token = jwt.encode(token_payload, jwt_secret, algorithm='HS256')

        return {
            'statusCode': 200,
            'headers': RESPONSE_HEADERS,
            'body': json.dumps({'token': jwt_token})
        }

    except Exception as err:
        print(f"Error: {str(err)}")
        return {
            'statusCode': 500,
            'headers': RESPONSE_HEADERS,
            'body': json.dumps({'message': 'Internal server error'})
        }
