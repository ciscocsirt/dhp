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


from .consts import *
from .util import *
from .notify import Notifier

import base64
import json
import logging
import traceback
import asyncio
import logging




class DockerHp(object):
    def __init__(self, sensor_id, sensor_ip, notifier, port=2375, 
                 terminate_with_error=True, error_message=ERROR_MESSAGE):
        self.sensor_ip = sensor_ip
        self.sensor_id = sensor_id
        self.notifier = notifier
        self.server = create_listener_sock(port) 
        self.terminate_with_error = terminate_with_error 
        self.error_message = error_message
        self.keep_working = False

        DOCKER_HP_LOGGER.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s :: %(name)s :: %(levelname)s :: %(message)s')
        ch.setFormatter(formatter)
        DOCKER_HP_LOGGER.addHandler(ch)

    async def consume_request(self, client, address, send_response=True):
        create_data = None
        src_ip, src_port = client.getpeername()
        dst_ip, dst_port = client.getsockname()
        created_at = get_iso_time()
        data = recv_until_done(client) #(client.recv(MAX_DATA))
        b64req = base64.b64encode(data).decode('ascii')
        if data == b'':
            DOCKER_HP_LOGGER.info("failed connection from: {}".format(address))
            return {'sensor_id': self.sensor_id, 'sensor_ip': self.sensor_ip,
                    'src_ip': src_ip, 'src_port': src_port, 'dst_ip': dst_ip, 'dst_port': dst_port, "created_at":created_at,
                    'rtype': UNKNOWN, 'response': None, "request": b64req, "request_data": None, "api": None, 'sent': False}
        rtype = get_handler_type(data)
        DOCKER_HP_LOGGER.info("Handling connection from {}:{} for {}".format(address[0], address[1], rtype))
        rdata = create_response(rtype, data)

        if data.find(b'Content-Type: application/json\r\n') > -1:
            create_data = extract_json_data(data)
        
        kargs = get_match_group(rtype, data)
        api = API if not 'api' in kargs else kargs['api'].decode('ascii').lstrip('v') 
        src_ip, src_port = client.getpeername()
        dst_ip, dst_port = client.getsockname()
        return {'sensor_id': self.sensor_id, 'sensor_ip': self.sensor_ip,
                'src_ip': src_ip, 'src_port': src_port, 'dst_ip': dst_ip, 'dst_port': dst_port, "created_at":created_at,
                'rtype': rtype, 'response': rdata, "request": b64req, 'request_data': create_data, 'api': api, 'sent': False }

    async def honeypot_connection(self, client, address, send_after_ping=False):
        result = await self.consume_request(client, address)
        results = [result]
        # facilitate follow-on docker client communication
        DOCKER_HP_LOGGER.info("Handled connection type:{} from {}:{}".format(result['rtype'], address[0], address[1]))
        if result['rtype'] == PING:
            client.send(result['response'].encode('ascii'))
            result['sent'] = True
        # Nothing else to do, likely a port scanner
        elif result['rtype'] == GET_VERSION or result['rtype'] == GET:
            client.send(result['response'].encode('ascii'))
            result['sent'] = True
            return results
        elif result['rtype'] == UNKNOWN:
            client.send(UNKNOWN_RETURN)
            result['sent'] = True
            return results

        result = await self.consume_request(client, address)
        results.append(result)

        if result['rtype'] and send_after_ping:
            try:
                client.send(result['response'].encode('ascii'))
                result['sent'] = True
            except:
                pass
        return results

    async def honeypot_next_client(self):
        client, address = self.server.accept()
        client.settimeout(3.0)
        results = await self.honeypot_connection(client, address)
        if len(results) < 2 or results[0]['rtype'] != PING:
            DOCKER_HP_LOGGER.info('Not a full honeypot connection') 
        elif self.terminate_with_error and len(results) >= 1 and results[0]['rtype'] == 'PING':
            created_at = get_iso_time()
            api = results[1]['api'] if results[1]['api'] else API 
            rdata = generate_error(api=api, error_message=self.error_message)
            src_ip, src_port = client.getpeername()
            dst_ip, dst_port = client.getsockname()

            result = {'sensor_id': self.sensor_id, 'sensor_ip': self.sensor_ip,
                      'src_ip': src_ip, 'src_port': src_port, 'dst_ip': dst_ip, 'dst_port': dst_port, 'created_at': created_at, 
                      'rtype': ERROR, 'response': rdata, 'request_data': None, 'api': api, 'sent': False}
            results.append(result)
            try:
                client.send(rdata.encode('ascii'))
                result = True
            except:
                pass
        return results

    async def doit(self):
        try:
            results = await self.honeypot_next_client()
            await self.notifier.notify(results)
        except:
            traceback.print_exc()

    async def serve_forever(self):
        self.keep_working = True
        while self.keep_working:
            await self.doit()

