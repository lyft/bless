"""
.. module: bless.request.bless_request
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import ipaddress
import re
from marshmallow import Schema, fields, post_load, ValidationError

# man 8 useradd
HOSTNAME_PATTERN = re.compile('[a-z0-9_.-]+')


def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValidationError('Invalid IP address.')


def validate_host(hostname):
    if len(hostname) > 64:
        raise ValidationError('Hostname is too long')
    if HOSTNAME_PATTERN.match(hostname) is None:
        raise ValidationError('Hostname contains invalid characters')


class BlessLyftSchema(Schema):
    public_key_to_sign = fields.Str()

    @post_load
    def make_bless_request(self, data):
        return BlessLyftRequest(**data)


class BlessLyftHostSchema(BlessLyftSchema):
    service_name = fields.Str()
    service_instance = fields.Str()
    service_region = fields.Str()
    kmsauth_token = fields.Str()
    instance_id = fields.Str()
    instance_availability_zone = fields.Str()
    onebox_name = fields.Str(allow_none=True)
    is_canary = fields.Bool()

    @post_load
    def make_bless_request(self, data):
        return BlessLyftHostRequest(**data)


class BlessLyftRequest:
    def __init__(self, public_key_to_sign):
        """
        A BlessRequest must have the following key value pairs to be valid.
        :param public_key_to_sign: The id_rsa.pub that will be used in the SSH request.  This is
        enforced in the issued certificate.
        """

        self.public_key_to_sign = public_key_to_sign

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class BlessLyftHostRequest(BlessLyftRequest):
    def __init__(self, public_key_to_sign, service_name, service_instance,
                 service_region, kmsauth_token, instance_id,
                 instance_availability_zone, onebox_name=None, is_canary=False):
        """
        A BlessRequest must have the following key value pairs to be valid.
        :param public_key_to_sign: The id_rsa.pub that will be used in the SSH request.  This is
        enforced in the issued certificate.
        :param service_name: The service name. This is used to generate hostnames and verify kmsauth.
        :param service_instance: The service instance name. This is used to generate hostnames
        and verify kmsauth. (e.g. staging, production)
        :param service_region: The service region name. This is used to generate hostnames
        and verify kmsauth. (e.g. iad, sfo)
        :param kmsauth_token: KMS auth token to authenticate the host
        :param instance_id: The instance id of the host
        :param instance_availability_zone: The availability zone of the host
        :param onebox_name: The name of the onebox (or None if it is not a onebox)
        :param is_canary: Whether the instance is a canary instance
        """

        self.public_key_to_sign = public_key_to_sign
        self.service_name = service_name
        self.service_instance = service_instance
        self.service_region = service_region
        self.kmsauth_token = kmsauth_token
        self.instance_id = instance_id
        self.instance_availability_zone = instance_availability_zone
        self.onebox_name = onebox_name
        self.is_canary = is_canary
