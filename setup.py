import os

from setuptools import setup, find_packages

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__)))

about = {}
with open(os.path.join(ROOT, "bless", "__about__.py")) as f:
    exec (f.read(), about)

setup(
    name=about["__title__"],
    version=about["__version__"],
    author=about["__author__"],
    author_email=about["__email__"],
    url=about["__uri__"],
    description=about["__summary__"],
    license=about["__license__"],
    packages=find_packages(exclude=["test*"]),
    install_requires=[
        'boto3==1.29.0',
        'botocore==1.32.0',
        'cffi==1.17.0',
        'cryptography==3.2.1',
        'docutils==0.15.2',
        'enum34>=1.1.6',
        'futures>=3.0.5',
        'idna>=2.1',
        'ipaddress==1.0.23',
        'jmespath==0.10.0',
        'marshmallow==2.19.2',
        'pyasn1>=0.1.9',
        'pycparser==2.19',
        'python-dateutil==2.8.0',
        'six==1.12.0',
        'kmsauth==0.6.3'
    ],
    extras_require={
        'tests': [
            'coverage',
            'flake8',
            'mccabe',
            'pep8',
            'py',
            'pyflakes',
            'pytest',
            'pytest-mock'
        ]
    }
)
