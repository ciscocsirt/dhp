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
import sys
import subprocess
from docker_honey.util import *
from docker_honey.collector_actions import *
from docker_honey.commands import *
from docker_honey.consts import GLOBAL_NOTIFIER as NOTIFIER
from docker_honey.consts import *
from docker_honey.notify import *
from docker_honey.simple_commands.app import Hypercorn as App
from docker_honey.simple_commands.util import *

from time import sleep
import asyncio
import argparse
from multiprocessing import Process
from quart import Quart, jsonify, Response, request
import json
import sys
from hypercorn.config import Config
from hypercorn.asyncio import serve

LOGGER = get_stream_logger(__name__)

# require installation
parser = argparse.ArgumentParser()
parser.add_argument("-config", help="json config to load from", default=None)
parser.add_argument("-submit", help="submit url to remote host", default=False, action="store_true")
parser.add_argument("-user_agent", help="user agent", default=DEFAULT_USER_AGENT)
parser.add_argument("-headers", help="headers", default={})
parser.add_argument("-url", help="url to submit", default=None)
parser.add_argument("-json_payload", help="json payloard to submit", default=None)
parser.add_argument("-data_parameters", help="data payload to submit", default=None)
parser.add_argument("-method", help="data payload to submit", default=None)
parser.add_argument("-sensor_id", help="sensor_id to submit to or 'all'", default=None)
parser.add_argument("-sensor_ip", help="sensor_ip to submit to or 'all'", default=None)


APP = None

async def submit_remote_request(**kargs):
    request_parameters =  CommandHandler.build_perform_web_request_payload(**kargs)
    sensor_ip = kargs.get('sensor_ip', None)
    sensor_id = kargs.get('sensor_id', None)
    if sensor_id is None:
        raise Exception("Sensor id not set.")

    skargs = {"sensor_ip":kargs.get("sensor_ip", None), 
              "sensor_id":kargs.get("sensor_id", None), 
              "token_value":kargs.get("token_value", None)}

    sensor_infos = get_single_notifier().get_sensor_infos(**skargs)
    print(sensor_infos, skargs)

    base_payload = {k: v for k, v in skargs.items() if not v is None}
    base_payload.update(request_parameters)
    for si in sensor_infos:
        payload = base_payload.copy()
        payload['sensor_ip'] = si.sensor_ip
        payload['sensor_id'] = si.sensor_id
        payload['token_value'] = si.token
        sensor_ip = sensor_ip if sensor_ip and len(sensor_infos) == 1 else si.sensor_ip
        sensor_id = sensor_id if sensor_id and len(sensor_infos) == 1 else si.sensor_id
        print(payload, sensor_id, sensor_ip)
        await CommandHandler.submit_remote_web_request(sensor_id, sensor_ip, DEFAULT_HP_LPORT, si.token, payload)






async def main(**args):
    global APP, NOTIFIER
    host = dargs.get('collector_host', '0.0.0.0')
    ca_name = dargs.get('collector_ca', 'ca-'+FAKE_COMMON_NAME)
    ca_crt = dargs.get('collector_ca_crt', ca_name+'.crt')
    server_crt = dargs.get('collector_crt', None)
    server_key = dargs.get('collector_key', None)
    port = dargs.get('collector_port', DEFAULT_HTTP_PORT)
    certs_path = dargs.get('certs_path', "./ssl")
    if ca_name is None:
        ca_name = "ca-collector"

    if server_crt is None or server_key is None:
        # common_name = 'collector'
        # server_key = "{}.key".format(common_name)
        # server_crt = "{}.crt".format(common_name)
        # create_certs(ca_name=ca_name, common_name=common_name, certs_path=certs_path)
        LOGGER.critical("Missing certificates for SSL, exiting")
        raise Exception("Missing certificates for SSL, exiting")

    dargs.update({"collector_crt": server_crt, 
                  "collector_key": server_key,
                  "ca_name": ca_name})


    dargs['is_collector'] = True
    NOTIFIER = get_single_notifier(**dargs)

    admin_token_info = await get_single_notifier().get_first_token()
    if admin_token_info is None:
        LOGGER.info("Missing first token, attempting to create it")
        email = dargs.get('first_admin_email', 'noon@localhost')
        name = dargs.get('first_admin_name', 'admin collector')
        description = dargs.get('first_admin_name', 'first admin token')
        _ = await get_single_notifier().create_first_admin(email=email, 
                                                           name=name, 
                                                           description=description)
        admin_token_info = await get_single_notifier().get_first_token()

    if admin_token_info is None:
        LOGGER.critical("No admin token found, failing")
        raise Exception("No admin token found, failing")

    use_admin_token = dargs.get('admin_token', None)
    use_admin_token_info = None
    if use_admin_token is not None:
        use_admin_token_info = await get_single_notifier().get_token(use_admin_token)

        if use_admin_token_info is None:
            use_admin_token_info = await get_single_notifier().add_token(admin_token_info.token, 
                                               use_admin_token,
                                               email=admin_token_info.email, 
                                               name=admin_token_info.name, 
                                               description='admin collector token', 
                                               is_admin=False, is_active=True)
    if use_admin_token_info is None:
        use_admin_token_info = admin_token_info


    _honeypot_tokens = dargs.get('honeypot_tokens', None)
    honeypot_tokens = None
    if isinstance(_honeypot_tokens, list) \
        and len(_honeypot_tokens) > 0:
        honeypot_tokens = []
        for token in sorted(set(_honeypot_tokens)):
            token_info = await get_single_notifier().get_token(token)
            if token_info:
                honeypot_tokens.append(token_info)
            else:
                token_info = await get_single_notifier().add_token(admin_token_info.token, 
                                       token,
                                       email=admin_token_info.email, 
                                       name=admin_token_info.name, 
                                       description='honeypot token', 
                                       is_admin=False, is_active=True)
                honeypot_tokens.append(token_info)
    if honeypot_tokens is None:
        honeypot_tokens = await get_single_notifier().get_honeypot_token_values()

    if honeypot_tokens is None or len(honeypot_tokens) == 0:
        honeypot_tokens = [await get_single_notifier().create_honeypot_token()]

    h_tokens = [hpt.token for hpt in honeypot_tokens]
    a_tokens = use_admin_token_info.token
    NOTIFIER.honeypot_tokens = h_tokens
    NOTIFIER.admin_token = a_tokens
    NOTIFIER.notify_collector_startup()

    app = App('docker-hp-collector', host='0.0.0.0', port=port, certs_path=certs_path,
              ca_crt=ca_crt, server_crt=server_crt, server_key=server_key)

    app.add_url_rule(REMOTE_REQUEST_ENDPOINT, 'basic_submit_web_request', handle_remote_web_request_page, methods = ['POST', 'GET'] )
    app.add_url_rule(EVENTS_ENDPOINT, 'events', handle_events, methods = ['POST', 'GET'])
    app.add_url_rule(REGISTER_ENDPOINT, 'register_sensor', handle_register, methods = ['POST'])
    app.add_url_rule(SUMMARY_ENDPOINT, 'remote_summary_downloads', handle_summary_downloads, methods = ['GET'])
    app.add_url_rule(DOWNLOAD_ENDPOINT, 'remote_file_downloads', handle_file_downloads, methods = ['GET'])
    app.add_url_rule(PING_ENDPOINT, 'ping', handle_ping, methods = ['POST'])
    app.add_url_rule(NEW_TOKEN_ENDPOINT, 'new_token', handle_new_token, methods = ['POST'])
    app.add_url_rule(COMMANDS_RESPONSE_ENDPOINT, 'remote_commands_response', handle_remote_command_responses, methods = ['POST'])
    app.add_url_rule(EVENT_ENDPOINT, 'get_event', handle_get_event, methods = ['GET'])

    LOGGER.info("Admin token for this instances is: {}".format(use_admin_token_info.token))    
    for hpt in honeypot_tokens:
        LOGGER.info("honeypot token that will be accepted for this instances is: {}".format(hpt.token))
    APP = app


if __name__ == '__main__':
    args = parser.parse_args()
    dargs = vars(args)

    if args.config:
        config_path = args.config
        del dargs[CONFIG]
        config = json.load(open(config_path))
        dargs.update(config)
    else:
        parser.print_help()
        sys.exit(-1)
    
    if dargs.get('global_hostname', None):
        dargs['global_hostname'] = get_external_ip()
        dargs['global_port'] = 5000


    if args.submit:
        NOTIFIER = get_single_notifier(**dargs)
        loop = asyncio.get_event_loop()
        # results = 
        asyncio.run(submit_remote_request(**dargs))
        sys.exit(0)


    loop = asyncio.get_event_loop()

    asyncio.run(main(**dargs))
    # cheating the nested event loops
    APP.quart_run()
