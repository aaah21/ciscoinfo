from setuptools import setup, find_packages
import sys
import os

REQUIRES = ['paramiko']
CURRENT_PATH = os.path.join(os.path.dirname(__file__))
sys.path.insert(1, CURRENT_PATH)

setup(
    name='CiscoInfo',
    version='1.0.0',
    url='https://github.com/aaah21/ciscoinfo.git',
    author='Aleandro Andrea',
    author_email='aaah1976@gmail.com',
    description='Library to query Cisco devices via ssh',
    packages=find_packages(),
    install_requires=REQUIRES,
)
