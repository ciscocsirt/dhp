__copyright__ = """

    Copyright 2020 Cisco Systems, Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

"""
__license__ = "Apache 2.0"

from docker_honey.server import DockerHp
from docker_honey.consts import *
from docker_honey.notify import Notifier
from time import sleep
import asyncio
import argparse
from multiprocessing import Process
import os

# require installation
parser = argparse.ArgumentParser()
parser.add_argument("-ports", help="ports to listen on", type=int,  nargs='+', default=PORTS)
parser.add_argument("-terminate_with_error", help="send a server error after create API call", action="store_true", default=False)
parser.add_argument("-error_message", help="error message to send after create API call", default=ERROR_MESSAGE, type=str)
parser.add_argument("-sensor_id", help="sensor identifier", default=DEFAULT_SENSOR_NAME, type=str)
parser.add_argument("-sensor_ip", help="sensor ip address", default=SENSOR_EXT_IP, type=str)

parser.add_argument("-http", help="send results to http endpoint", default=False, action='store_true')
parser.add_argument("-http_url", help="http endpoint url", default=None, type=str)
parser.add_argument("-http_verify_ssl", help="verify ssl (if no certificates specified)", default=HTTP_VERIFY_SSL, action='store_true')
parser.add_argument("-http_client_key", help="client key for authentication", default=None, type=str)
parser.add_argument("-http_client_crt", help="client certificate for authentication", default=None, type=str)
parser.add_argument("-http_server_crt", help="server certificate for authentication", default=None, type=str)
parser.add_argument("-http_token", help="http token", default=None, type=str)
parser.add_argument("-http_port", help="http port", default=None, type=int)


parser.add_argument("-use_mongo", help="use mongo", default=False, action='store_true')
parser.add_argument("-mongo_db", help="mongo database to connect to", default=DATABASE, type=str)
parser.add_argument("-mongo_host", help="mongo host to connect to", default='127.0.0.1', type=str)
parser.add_argument("-mongo_port", help="mongo port go connect to", default=27017, type=int)
parser.add_argument("-mongo_user", help="mongo username", default=None, type=str)
parser.add_argument("-mongo_pass", help="mongo password", default=None, type=str)

parser.add_argument("-email", help="notify about attempt", action='store_true', default=False)
parser.add_argument("-email_notify_subject", help="email subject line", default=DEFAULT_SUBJECT, type=str)
parser.add_argument("-email_server", help="email server", default="smtp.gmail.com", type=str)
parser.add_argument("-email_port", help="email port", default=587, type=int)
parser.add_argument("-email_username", help="email server", default=None, type=str)
parser.add_argument("-email_password", help="email password", default=None, type=str)
parser.add_argument("-email_cc_list", help="email cc list", nargs='+', default=None, type=str)


# parser.add_argument("-slack_token", help="someone to email when event happens", default=None, type=str)
parser.add_argument("-slack", help="notify about attempt", action='store_true', default=False)
parser.add_argument("-slack_channel", help="slack channel tp post too", default=None, type=str)
parser.add_argument("-slack_username", help="username for webhook", default='docker_honyepot', type=str)
parser.add_argument("-slack_webhook", help="webhook url", default=None, type=str)
parser.add_argument("-slack_emoticon", help="slack emoticon to use", default=":suspect:", type=str)

parser.add_argument("-wbx", help="notify about attempt", action='store_true', default=False)
parser.add_argument("-wbx_webhook", help="webhook url", default=None, type=str)

check_empty_string = lambda x: isinstance(x, str) and len(x) == 0

def http_environ(dargs):
    dargs['http'] = bool(dargs.get('http', None))
    if check_empty_string(dargs['http']):
        dargs['http'] = None
    dargs['http_url'] = dargs.get('http_url', None)
    if check_empty_string(dargs['http_url']):
        dargs['http_url'] = None
    dargs['http_verify_ssl'] = dargs.get('http_verify_ssl', None)
    if check_empty_string(dargs['http_verify_ssl']):
        dargs['http_verify_ssl'] = None
    dargs['http_client_key'] = dargs.get('http_client_key', None)
    if check_empty_string(dargs['http_client_key']):
        dargs['http_client_key'] = None
    dargs['http_client_crt'] = dargs.get('http_client_crt', None)
    if check_empty_string(dargs['http_client_crt']):
        dargs['http_client_crt'] = None
    dargs['http_server_crt'] = dargs.get('http_server_crt', None)
    if check_empty_string(dargs['http_server_crt']):
        dargs['http_server_crt'] = None
    dargs['http_token'] = dargs.get('http_token', None)
    if check_empty_string(dargs['http_token']):
        dargs['http_token'] = None
    if check_empty_string(dargs['http_token']):
        dargs['http_token'] = None
    if check_empty_string(dargs['http_port']):
        dargs['http_port'] = None
    else:
        dargs['http_port'] = int(dargs['http_port'])

def mongo_environ(dargs):
    dargs['use_mongo'] = bool(dargs.get('use_mongo', None))
    dargs['mongo_db'] = dargs.get('mongo_db', None)
    if check_empty_string(dargs['mongo_db']):
        dargs['mongo_db'] = DATABASE
    dargs['mongo_host'] = dargs.get('mongo_host', None)
    if check_empty_string(dargs['mongo_host']):
        dargs['mongo_host'] = '127.0.0.1'
    dargs['mongo_port'] = dargs.get('mongo_port', None)
    if check_empty_string(dargs['mongo_port']):
        dargs['mongo_port'] = 27017
    else:
        dargs['mongo_port'] = int(dargs['mongo_port'])

    dargs['mongo_user'] = dargs.get('mongo_user', None)
    if check_empty_string(dargs['mongo_user']):
        dargs['mongo_user'] = None
    dargs['mongo_pass'] = dargs.get('mongo_pass', None)
    if check_empty_string(dargs['mongo_pass']):
        dargs['mongo_pass'] = None

def wbx_environ(dargs):
    dargs["wbx"] = bool(dargs.get('wbx', None))
    dargs["wbx_webhook"] = dargs.get('wbx_webhook', None)
    if check_empty_string(dargs["wbx_webhook"]):
        dargs["wbx_webhook"] = None

def slack_environ(dargs):
    dargs["slack"] = bool(dargs.get("slack", None))
    dargs["slack_channel"] = dargs.get("slack_channel", None)
    if check_empty_string(dargs["slack_channel"]):
        dargs["slack_channel"] = None
    dargs["slack_username"] = dargs.get("slack_username", None)
    if check_empty_string(dargs["slack_username"]):
        dargs["slack_username"] = None
    dargs["slack_webhook"] = dargs.get("slack_webhook", None)
    if check_empty_string(dargs["slack_webhook"]):
        dargs["slack_webhook"] = None
    dargs["slack_emoticon"] = dargs.get("slack_emoticon", None)
    if check_empty_string(dargs["slack_emoticon"]):
        dargs["slack_emoticon"] = None

def update_eviron(dargs)
    http_environ(dargs)
    mongo_environ(dargs)
    wbx_environ(dargs)
    slack_environ(dargs)
    return dargs
    

def main(sensor_id, sensor_ip, notifier, port, terminate_with_error, error_message):
    honeypot = DockerHp(sensor_id, sensor_ip, notifier, port=port, 
                        terminate_with_error=terminate_with_error, error_message=error_message)
    loop = asyncio.get_event_loop()
    loop.create_task(honeypot.serve_forever())
    loop.run_forever()

@app.route('/', methods = ['GET'])
def index():
    pass

@app.route('/events/', methods = ['POST', 'GET'])
def handle_events():
    pass

@app.route('/register/', methods = ['POST', 'GET'])
def handle_register():
    pass

if __name__ == "__main__":
    dargs = update_eviron(os.environ.copy())

    _ports = dargs.get('ports', PORTS)
    ports = PORTS
    if isinstance(_ports, str) and _ports.find(' ') > -1:
        ports = [int(i) for i in _ports.split() if len(i) > 0]
    if isinstance(_ports, str) and _ports.find(',') > -1:
        ports = [int(i.strip()) for i in _ports.split(',') if len(i.strip()) > 0]

    if not isinstance(ports, list) or len(ports) == 0:
        ports = PORTS
    
    terminate_with_error = 'terminate_with_error' in dargs
    error_message = dargs['error_message'] if 'error_message' in dargs else ERROR_MESSAGE
    sensor_id = dargs['sensor_id'] if 'sensor_id' in dargs else DEFAULT_SENSOR_NAME
    sensor_id = dargs['sensor_ip'] if 'sensor_ip' in dargs else SENSOR_EXT_IP
    
    notifier = Notifier(sensor_id, sensor_ip, **dargs)