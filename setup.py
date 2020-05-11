from setuptools import setup, find_packages

setup(
    name='CiscoInfo',
    version='1.0.0',
    url='https://github.com/ciscoinfo.git',
    author='Aleandro Andrea',
    author_email='aaah1976@gmail.com',
    description='Library to query Cisco devices via ssh',
    packages=find_packages(),
    install_requires=['time', 'paramiko', 'datetime', 'os' ],
)