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
import json
import zipfile
import asyncio
import io
import traceback
import base64
from .simple_commands.util import *

class CommandHandler(object):
    LOGGER = get_stream_logger(__name__ + '.CommandHandler')
    @classmethod
    def execute_post(cls, collector_url, payload, verify=False):
        rsp = None
        host = collector_url.split("://")[1].split("/")[0]
        try:
            rsp = requests.post(collector_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'},
                          verify=verify, timeout=3.001)
        except:
            cls.LOGGER.info("Failed to connect to {}.".format(host))

        finally:
            if rsp:
                cls.LOGGER.info("Connected to {} with response:{}.".format(host, rsp.status_code))
            if rsp and rsp.status_code == 200:
                return True
        return False

    @classmethod
    async def handle_commands(cls, **kargs):

        if COMMAND not in kargs:
            cls.LOGGER.info("No command specified, returning.".format())
            return None
        elif kargs[COMMAND] == REMOTE_WEB_REQUEST_CMD:
            cls.LOGGER.info("Handling '{}'.".format(REMOTE_WEB_REQUEST_CMD))
            response = await cls.perform_web_request(**kargs.get(REQUEST_PARAMETERS, {}))
            response[COMMAND] = REMOTE_WEB_REQUEST_CMD
            cls.LOGGER.info("Completed '{}'.".format(REMOTE_WEB_REQUEST_CMD))
            return response
        return None

    @classmethod
    async def submit_remote_web_request_cmd(cls, sensor_id, sensor_ip, port, token, payload):
        url = "https://{}:{}".format(sensor_ip, port) + HP_COMMAND_ENDPOINT
        cls.LOGGER.info("Submitting remote web request to {}:{}.".format(sensor_id, url))
        payload[TOKEN] = token
        payload[SENSOR_ID] = sensor_id
        payload[SENSOR_IP] = sensor_ip
        payload[COMMAND] = REMOTE_WEB_REQUEST_CMD
        payload[DATETIME] = get_iso_time()
        # cls.LOGGER.info("Submitting payload:\n {}\n".format(payload))
        return cls.execute_post(url, payload)
        

    @classmethod
    def build_perform_web_request_payload(cls, url, user_agent=DEFAULT_USER_AGENT, parameters=None, data_payload=None, json_payload=None,
                                  headers=None, method=GET, **kargs):
        if headers is None:
            headers = {}

        if method is None:
            method = GET

        if (data_payload or json_payload) and method == GET:
            method = POST

        request_parameters = {
            HEADERS: headers,
            METHOD: method, 
            PARAMETERS: parameters,
            DATA_PAYLOAD: data_payload,
            JSON_PAYLOAD: json_payload,
            URL: url,
            USER_AGENT: user_agent,
        }

        return {REQUEST_PARAMETERS: request_parameters, COMMAND: COMMAND_PERFORM_WEBREQ}

    @classmethod
    async def perform_web_request(cls, **kargs):
        user_agent = kargs.get(USER_AGENT, DEFAULT_USER_AGENT)
        parameters = kargs.get(PARAMETERS, None)
        json_payload = kargs.get(JSON_PAYLOAD, None)
        data_payload = kargs.get(DATA_PAYLOAD, None)
        headers = kargs.get(HEADERS, {})
        method = kargs.get(METHOD, GET)
        url = kargs.get(URL, None)
        cls.LOGGER.info("Submitting {} request for url {}.".format(method, url))
        req_meth = requests.get
        if method == GET:
            pass
        elif method == POST:
            req_meth = requests.post
        elif method == PUT:
            req_meth = requests.post

        rsp = None
        response_info = {
            STATUS_CODE: -1, 
            HISTORY: [],
            URL: url,
            CONTENT: None,
            HEADERS: None,
            DATETIME: get_iso_time(),
            CONTENT: None,
            CONTENT_ENCODING: None,
            CONTENT_TYPE: None,
        }
        if headers is None:
            headers = {USER_AGENT_HEADER:user_agent}
        if USER_AGENT_HEADER not in headers:
            headers[USER_AGENT_HEADER] = headers
        try:
            rsp = req_meth(url, json=json_payload, 
                                data=data_payload, 
                                params=parameters,
                                headers=headers,
                                verify=False)
            data = b''
            response_info = {
                STATUS_CODE: rsp.status_code, 
                HISTORY: [] if rsp.history is None else [{STATUS_CODE:i.status_code, URL:i.url} for i in rsp.history],
                URL: rsp.request.url,
                CONTENT: data,
                HEADERS: list(rsp.headers.items()),
                DATETIME: get_iso_time(),
                "client_headers": headers,
            }

            if rsp.content and len(rsp.content) > 0:
                memzf = io.BytesIO()
                zf = zipfile.ZipFile(memzf, "a", zipfile.ZIP_DEFLATED, False)
                summary = ''
                summary = "[Request Details]\n" + "\n".join(['{}: {}'.format(k, v) for k,v in kargs.items()])
                summary = summary + "\n[History]\n"
                summary = summary + "\n".join(["{} {}".format(i.status_code, i.history) for i in rsp.history])
                summary = summary + "\n[Content]\n"
                summary = summary + 'Length: {}'.format(len(rsp.content))
                summary = summary + '\n[Response Headers]\n' + "\n".join(['{}: {}'.format(k, v) for k,v in rsp.headers.items()])
                zf.writestr('summary.txt', summary.encode('ascii'))
                zf.writestr('content.bin', rsp.content)
                zf.close()
                memzf.seek(0)
                data = base64.b64encode(memzf.read())
                response_info[CONTENT] = data.decode('ascii')
                response_info[CONTENT_ENCODING] = BASE64
                response_info[CONTENT_TYPE] = CONTENT_TYPE_ZIP
        except:
            cls.LOGGER.info("Request failed {} request for url {}.".format(method, url))
            cls.LOGGER.info("Request failed {} request for url {}.".format(method, url))
            memzf = io.BytesIO()
            zf = zipfile.ZipFile(memzf, "a", zipfile.ZIP_DEFLATED, False)
            summary = 'Failed to connect: {}\n{}'.format(url, traceback.format_exc())
            zf.writestr('summary.txt', summary.encode('ascii'))
            zf.writestr('content.bin', b'')
            zf.close()
            memzf.seek(0)
            data = base64.b64encode(memzf.read())
            response_info[CONTENT] = data.decode('ascii')
            response_info[CONTENT_ENCODING] = BASE64
            response_info[CONTENT_TYPE] = CONTENT_TYPE_ZIP


        cls.LOGGER.info("Request completed {} request for url {} with status_code: {}.".format(method, url, response_info[STATUS_CODE]))
        results = {RESPONSE_INFO: response_info, REQUEST_PARAMETERS: kargs, COMMAND: REMOTE_WEB_REQUEST_CMD}
        return results
