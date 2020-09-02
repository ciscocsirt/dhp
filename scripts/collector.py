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

from docker_honey.util import *
from docker_honey.consts import *
from docker_honey.notify import *
from time import sleep
import asyncio
import argparse
from multiprocessing import Process
from quart import Quart, jsonify, Response, request
import json


# require installation
parser = argparse.ArgumentParser()
parser.add_argument("-http", help="send results to http endpoint", default=False, action='store_true')
parser.add_argument("-http_url", help="http endpoint url", default=None, type=str)
parser.add_argument("-http_verify_ssl", help="verify ssl (if no certificates specified)", default=HTTP_VERIFY_SSL, action='store_true')
parser.add_argument("-http_client_key", help="client key for authentication", default=None, type=str)
parser.add_argument("-http_client_crt", help="client certificate for authentication", default=None, type=str)
parser.add_argument("-http_server_crt", help="server certificate for authentication", default=None, type=str)
parser.add_argument("-http_server_ca", help="server certificate for authentication", default=None, type=str)
parser.add_argument("-http_port", help="http port", default=DEFAULT_HTTP_PORT, type=str)


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
parser.add_argument("-slack_username", help="username for webhook", default='docker_honey', type=str)
parser.add_argument("-slack_webhook", help="webhook url", default=None, type=str)
parser.add_argument("-slack_emoticon", help="slack emoticon to use", default=":suspect:", type=str)

parser.add_argument("-wbx", help="notify about attempt", action='store_true', default=False)
parser.add_argument("-wbx_webhook", help="webhook url", default=None, type=str)

app = Quart(__name__)
@app.route('/')
def index():
    pass

@app.route('/events', methods = ['POST', 'GET'])
async def handle_events():
    global NOTIFIER
    events = None
    try:
        payload = json.loads(await request.data)
        events = payload[EVENTS]
        token = payload[TOKEN]
        sensor_ip = payload[SENSOR_IP]
        sensor_id = payload[SENSOR_ID]
        DOCKER_HP_LOGGER.info("Recv'd {} events from {} ({})".format(len(events), sensor_id, sensor_ip))
        if NOTIFIER:
            await NOTIFIER.collector_notify(events)
        print('results returned')
    except:
        print (traceback.print_exc())
    return Response('', status=200)

@app.route('/register', methods = ['POST'])
def handle_register():
    global NOTIFIER
    events = None
    try:
        payload = json.loads(await request.data)
        sensor_ip = payload[SENSOR_IP]
        sensor_id = payload[SENSOR_ID]
        token = payload[TOKEN]
        dt = payload[DATETIME]
        now = get_iso_time()
        DOCKER_HP_LOGGER.info("Recv'd registration from {} ({})".format(sensor_id, sensor_ip))
        if NOTIFIER:
            await NOTIFIER.ping_sensor(sensor_id, sensor_ip, token, dt, now)
        print('results returned')
    except:
        print (traceback.print_exc())
    return Response('', status=200)


@app.route('/ping', methods = ['POST'])
def handle_ping():
    global NOTIFIER
    events = None
    try:
        payload = json.loads(await request.data)
        sensor_ip = payload[SENSOR_IP]
        sensor_id = payload[SENSOR_ID]
        token = payload[TOKEN]
        dt = payload[DATETIME]
        now = get_iso_time()
        DOCKER_HP_LOGGER.info("Recv'd ping from {} ({})".format(sensor_id, sensor_ip))
        if NOTIFIER:
            await NOTIFIER.ping_sensor(sensor_id, sensor_ip, token, dt, now)
        print('results returned')
    except:
        print (traceback.print_exc())
    return Response('', status=200)

if __name__ == '__main__':
    args = parser.parse_args()
    dargs = vars(args)
    
    server_ca = dargs.get('http_server_ca', None)
    server_crt = dargs.get('http_server_crt', None)
    server_key = dargs.get('http_server_key', None)
    http_port = dargs.get('http_port', DEFAULT_HTTP_PORT)

    NOTIFIER = Notifier(**dargs)

    context = None
    if server_ca is not None and \
       server_crt is not None and \
       server_key is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_verify_locations(server_ca)
        context.load_cert_chain(server_crt, server_key)
    
    
    app.run('0.0.0.0', http_port, ssl_context=context)

