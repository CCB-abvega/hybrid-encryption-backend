import os
from ccb_itproy_toolbox import createApiGateWayResponse, get_secret, encrypt_data
from ccb_core_annotations import ccb_lambda_function, logger
import base64
import boto3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import json
from aws_lambda_powertools import Logger

logger = Logger()


def wrap_dek(dek: bytes, public_key: str) -> bytes:

    kms_client = boto3.client('kms')
    keyDER = base64.b64decode(public_key)
    public_key = RSA.import_key(keyDER)
    cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    decoded_encrypted_dek = base64.b64decode(dek)
    response = kms_client.decrypt(
        CiphertextBlob=decoded_encrypted_dek
    )

    plaintext_dek = response['Plaintext']
    encrypted_data_key = cipher_rsa.encrypt(plaintext_dek)
    encoded_encrypted_data_key = base64.b64encode(encrypted_data_key)
    return encoded_encrypted_data_key


@ccb_lambda_function("True")
def lambda_handler(event, context, process_init_time: float):
    body = json.loads(event['body'])
    aws_id = context.aws_request_id
    public_key = body.get('public_key')
    logger.info(f"Public Key: {public_key}")

    encrypted_dek = get_secret(
        os.environ.get('ENCRYPTED_DEK_SECRET'))['encrypted_dek']

    data_to_be_encrypted = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit, "
                            "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
                            "Diam maecenas ultricies mi eget mauris pharetra et. Nunc non blandit "
                            "massa enim nec dui nunc mattis enim. Vestibulum lectus mauris ultrices "
                            "eros in cursus turpis massa. Dui accumsan sit amet nulla facilisi morbi "
                            "tempus. Nibh tellus molestie nunc non blandit massa enim nec. Eu scelerisque "
                            "felis imperdiet proin. Praesent tristique magna sit amet purus gravida quis. "
                            "Mollis aliquam ut porttitor leo a diam. Massa eget egestas purus viverra accumsan "
                            "in. Fermentum iaculis eu non diam. Nibh cras pulvinar mattis nunc sed blandit libero. "
                            "Aliquam etiam erat velit scelerisque in dictum. Tincidunt id aliquet risus feugiat in "
                            "ante metus. Commodo odio aenean sed adipiscing diam donec. Placerat duis ultricies lacus "
                            "sed. Posuere lorem ipsum dolor sit amet consectetur adipiscing. Malesuada fames ac turpis "
                            "egestas maecenas pharetra convallis posuere morbi. Pharetra diam sit amet nisl suscipit "
                            "adipiscing bibendum.")

    encrypted_data = encrypt_data(
        data=data_to_be_encrypted, encrypted_dek=encrypted_dek)
    wrapped_dek = wrap_dek(encrypted_dek, public_key)

    test_response = {
        "encrypted_data": encrypted_data,
        "encrypted_data_key": wrapped_dek.decode('utf-8')
    }
    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    }
    return createApiGateWayResponse(200, test_response, aws_id, headers=headers)
