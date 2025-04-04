import json
import time

def lambda_handler(event, context):
    # Generate the current UNIX timestamp (in seconds)
    timestamp = int(time.time())

    # Return a JSON response with HTTP 200 and the current timestamp
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json'
        },
        'body': json.dumps({
            'timestamp': timestamp
        })
    }
