import pytest
from bless.request.bless_request_lyft_host import BlessLyftHostSchema, validate_host
from bless.request.bless_request_host import HOSTNAME_VALIDATION_OPTIONS
from marshmallow import ValidationError


@pytest.mark.parametrize("test_input", [
    'thisthat',
    'this.that',
    '10.1.1.1'
])
def test_validate_hostnames(test_input):
    validate_host(test_input)


@pytest.mark.parametrize("test_input", [
    '%&&&&',
    '',
    'carzylongkdjfldksjfkldsfjlkdsjflkdsjflkdsjfkldjfkldjfdlkjfdkljdflkjslkdfjkldfjldk',
])
def test_invalid_host(test_input):
    with pytest.raises(ValidationError) as e:
        validate_host(test_input)


@pytest.mark.parametrize("test_input", [
    'this..that',
    'this!that.com',
    'this,that'
])
def test_invalid_hostnames_with_disabled(test_input):
    validate_host(test_input)



