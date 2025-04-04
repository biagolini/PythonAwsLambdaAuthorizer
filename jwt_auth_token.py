import os
import jwt
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variable containing the secret key used to sign JWTs
JWT_SECRET = os.environ.get('JWT_SECRET', '')
if not JWT_SECRET:
    logger.warning("Environment variable 'JWT_SECRET' is not set. Using an empty string as default.")

# List of allowed API Gateway method ARNs (can be adjusted to support multiple routes)
ALLOWED_RESOURCE_ARNS = [
    "arn:aws:execute-api:us-east-1:123456789012:api-id/dev/GET/api",
    "arn:aws:execute-api:us-east-1:123456789012:api-id/ESTestInvoke-stage/GET/"
]

def lambda_handler(event, context):    
    logger.info(f"Received event: {event}")    
    token = event.get('authorizationToken')
    method_arn = event.get('methodArn')

    if not token:
        raise Exception('Unauthorized')  # Triggers HTTP 401

    if token.lower().startswith('bearer '):
        token = token[7:]  # Removes the "Bearer " prefix

    try:
        # JWT token validation
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = decoded.get('user_id')

        if not user_id:
            raise Exception("Unauthorized")

        # Check if the resource is authorized
        if method_arn not in ALLOWED_RESOURCE_ARNS:
            effect = 'Deny'
        else:
            effect = 'Allow'

        return generate_policy(principal_id=user_id, effect='Allow', resource='*')

    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        raise Exception('Unauthorized')
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        raise Exception('Unauthorized')
    except Exception as e:
        logger.error(f"Authorization error: {e}")
        raise Exception('Unauthorized')

def generate_policy(principal_id, effect, resource):
    """
    Generates an IAM policy in the format expected by API Gateway
    """
    auth_response = {
        'principalId': principal_id
    }

    if effect and resource:
        auth_response['policyDocument'] = {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': resource
            }]
        }

    # Optional: additional context that can be passed to the protected Lambda function
    auth_response['context'] = {
        'user_id': principal_id,
        'authorized': effect == 'Allow'
    }

    return auth_response
