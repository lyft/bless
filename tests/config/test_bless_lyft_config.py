import os

import pytest

from bless.config.bless_lyft_config import BlessLyftConfig


def test_empty_config():
    with pytest.raises(ValueError):
        BlessLyftConfig('us-west-2', config_file='')


def test_config_no_password():
    with pytest.raises(ValueError) as e:
        BlessLyftConfig('bogus-region',
                        config_file=os.path.join(os.path.dirname(__file__), 'full.cfg'))
    assert 'No Region Specific Password Provided.' == str(e.value)


def test_getpassword():
    config = BlessLyftConfig('us-east-1', config_file=(os.path.join(os.path.dirname(__file__), 'full-lyft.cfg')))

    assert config.getpassword() == 'pretend_password'
