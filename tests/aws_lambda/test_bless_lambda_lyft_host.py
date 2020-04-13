import os
import pytest

from bless.aws_lambda.bless_lambda_lyft_host import lambda_lyft_host_handler
from tests.ssh.vectors import EXAMPLE_RSA_PUBLIC_KEY, RSA_CA_PRIVATE_KEY_PASSWORD


class Context(object):
    aws_request_id = 'bogus aws_request_id'
    invoked_function_arn = 'bogus invoked_function_arn'


VALID_TEST_REQUEST = {
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "hostnames": "thisthat.com",
    'service_name': 'testy',
    'service_instance': 'testing-staging-iad-03ab45f10397e780a.lyft.net',
    'service_region': 'us-east-1',
    'kmsauth_token': 'AABB',
    'instance_id': 'testing-staging-iad-03ab45f10397e780a',
    'instance_availability_zone': 'us-east-1'
}

VALID_TEST_REQUEST_MULTIPLE_HOSTS = {
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "hostnames": "thisthat.com,thatthis.com",
}

INVALID_TEST_REQUEST = {
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "hostname": "thisthat.com",  # Wrong key name
}

os.environ['AWS_REGION'] = 'us-west-2'


def test_basic_local_request(mocker):
    mocker.patch("kmsauth.KMSTokenValidator.decrypt_token")
    # Below involves assuming a role on AWS
    mocker.patch('bless.aws_lambda.bless_lambda_lyft_host.validate_instance_id', return_value=True)
    output = lambda_lyft_host_handler(VALID_TEST_REQUEST, context=Context,
                                      ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                                      entropy_check=False,
                                      config_file=os.path.join(os.path.dirname(__file__), 'lyft-full.cfg'))

    assert output
