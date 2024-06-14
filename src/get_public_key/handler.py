import os
from ccb_itproy_toolbox import createApiGateWayResponse
from ccb_core_annotations import ccb_lambda_function
import boto3
import json
import base64
from aws_lambda_powertools import Logger
logger = Logger()

client = boto3.client('dynamodb')
kms_client = boto3.client('kms')
table_name = 'Decryption_keys'


def get_public_key(id: str):
    key = {
        'id': {'S': id}
    }
    response = client.get_item(TableName=table_name, Key=key)
    item = response.get('Item')
    if item:
        public_key_id = item.get('key', {}).get('S')
        if public_key_id:
            response = kms_client.get_public_key(KeyId=public_key_id)
            public_key_der = response['PublicKey']
            logger.info(f"Public key retrieved successfully: {public_key_der}")
            return base64.b64encode(public_key_der).decode('utf-8')
    else:
        logger.error(f"The 'key' {id} is not found in the item.")
        raise Exception("The 'key' key is not found in the item.")


@ccb_lambda_function("True")
def lambda_handler(event, context, process_init_time: float):
    body = json.loads(event['body'])
    aws_id = context.aws_request_id
    user_id = body.get('user_id')
    public_key = get_public_key(user_id)
    test_response = {
        "public_key": public_key,
    }
    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    }
    return createApiGateWayResponse(200, test_response, aws_id, headers=headers)
