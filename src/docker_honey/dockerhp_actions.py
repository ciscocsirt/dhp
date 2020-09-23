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

from .util import *
from .consts import GLOBAL_NOTIFIER as NOTIFIER
from .consts import *
from .notify import *
from .simple_commands.app import Hypercorn as App
from time import sleep
import asyncio
import argparse
from quart import Quart, jsonify, Response, request
import json
from .simple_commands.util import *

LOGGER = get_stream_logger(__name__)

async def handle_remote_commands():
    global NOTIFIER
    events = None
    try:
        payload = json.loads(await request.data)
        token = payload.get(TOKEN, '')
        sensor_ip = payload.get(SENSOR_IP, None)
        sensor_id = payload.get(SENSOR_ID, None)
        dt = payload.get(DATETIME, None)
        now = get_iso_time()
        LOGGER.info("Recv'd remote commands requests from {} ({})".format(sensor_id, sensor_ip))
        if sensor_id is None or sensor_ip is None or token is None or dt is None:
            return Response('', status=200)

        secret_target_token = get_single_notifier().server_secret_key
        secret_target_match = secret_target_token == token
        LOGGER.info("Authenticated incoming request with 'server_secret_key': sst: {} token{}".format(secret_target_token, token))
        if not secret_target_match:
            return Response('', status=403)            

        LOGGER.info("Authenticated incoming request with 'server_secret_key'")
        if notifier_initted():
            get_single_notifier().start_process_commands(sensor_id, sensor_ip, token, payload)
    except:
        traceback.print_exc()
        return Response('', status=500)
    return Response('', status=200)