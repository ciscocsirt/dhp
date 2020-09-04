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

import asyncio
import ssl
import uuid
import traceback
import requests
import json
import urllib
from .commands import CommandHandler
from .consts import *
from .util import *
from .mongo_orm import *
from mongoengine import connect
from multiprocessing import Process
from .simple_commands.util import *
import logging

def get_single_notifier(**kargs):
    if Notifier.GLOBAL_NOTIFIER is None:
        return Notifier(**kargs)
    return Notifier.GLOBAL_NOTIFIER

def notifier_initted():
    return not Notifier.GLOBAL_NOTIFIER is None


class Notifier(object):
    GLOBAL_NOTIFIER = None
    PROCESSES = []
    LOGGER = get_stream_logger(__name__ + '.Notifier')
    def get_base_payload(self, use_secret_key=False):
        token = self.collector_kargs['collector_token']
        if use_secret_key:
            token = self.server_secret_key
        return {TOKEN: token, 
                SENSOR_ID: self.sensor_id, 
                SENSOR_IP: self.sensor_ip,
                DATETIME: get_iso_time(),}

    def __init__(self, sensor_id=DEFAULT_SENSOR_NAME, sensor_ip=SENSOR_EXT_IP, 
                 is_collector=False, log_level=logging.DEBUG, **kargs):
        reset_logger_level(self.LOGGER, log_level)
        self.sensor_id = sensor_id
        self.sensor_ip = sensor_ip
        self.is_collector = is_collector
        self.server_secret_key = kargs.get('server_secret_key', None)
        
        self.slack_kargs = {}
        self.collector_kargs = {}
        self.mongo_kargs = {}
        self.wbx_kargs = {}
        self.email_kargs = {}
        self.elk_kargs = {}
        self.honeypot_tokens = []
        self.admin_token = None
    

        for k, v in GLOBAL_CONFIGS.items():
            setattr(self, k, kargs.get(k, v))

        self.mongo_kargs = {k: kargs.get(k, v) for k,v in MONGO_DEFAULTS.items()}
        self.slack_kargs = {k: kargs.get(k, v) for k,v in SLACK_DEFAULTS.items()}
        self.wbx_kargs = {k: kargs.get(k, v) for k,v in WBX_DEFAULTS.items()}
        self.collector_kargs = {k: kargs.get(k, v) for k,v in COLLECTOR_HTTP_DEFAULTS.items()}
        self.dockerhp_kargs = {k: kargs.get(k, v) for k,v in DOCKERHP_HTTP_DEFAULTS.items()}

        self.allowed_token = kargs.get(ALLOWED_TOKEN, None)
        Notifier.GLOBAL_NOTIFIER = self
        # self.GLOBAL_NOTIFIER = self
        
        self.collector_kargs['collector_url'] = self.collector_kargs['collector_url_fmt'].format(**self.collector_kargs).strip("/")
        self.dockerhp_kargs['dockerhp_url'] = self.dockerhp_kargs['dockerhp_url_fmt'].format(**self.dockerhp_kargs)

        if self.mongo_kargs['mongo']:            
            self.mongo_kargs['mongo_encode_password'] = urllib.parse.quote(self.mongo_kargs['mongo_pass'])
            self.mongo_kargs['mongo_host_uri'] = "mongodb://{mongo_user}:{mongo_encode_password}@{mongo_host}:{mongo_port}/".format(**self.mongo_kargs)
            self.mc = connect(self.mongo_kargs['mongo_db'], host=self.mongo_kargs['mongo_host_uri'], 
                    port=self.mongo_kargs['mongo_port'],
                    # db=self.mongo_kargs['mongo_db'],
                    username=self.mongo_kargs['mongo_user'],
                    password=self.mongo_kargs['mongo_pass'],
                    ssl=self.mongo_kargs['mongo_ssl'], 
                    ssl_cert_reqs=ssl.CERT_NONE,
                    authentication_source="admin")

        # if self.is_collector:
        #     self.notify_collector_startup()

    def get_collector_token(self):
        return self.collector_kargs.get('collector_token', None)

    def notify_collector_startup(self):
        
        token = self.admin_token
        cnt = 1
        _tokes = []
        for t in self.honeypot_tokens:
            _tokes.append('{}. `{}`'.format(cnt, t))
            cnt += 1
        h_tokens = '\n'.join(_tokes)        
        
        message = "Collector Startup: Access remote commands: https://{}:{}/remote_web_request\n\n**Admin token:** `{}`\n\n**Honeypot Tokens:**\n{}".format(self.global_hostname, self.global_port, token, h_tokens)
        # self.LOGGER.info(message)
        if self.wbx_kargs['wbx']:
            webhook_url = self.wbx_kargs['wbx_webhook']
            requests.post(webhook_url, data=json.dumps({'markdown': message}), headers={'Content-Type': 'application/json'})

        if self.slack_kargs['slack']:
            message = "Collector Startup: Access remote commands: https://{}:{}/remote_web_request\n\n*Admin token:* `{}`\n\n*Honeypot Tokens:*\n{}".format(self.global_hostname, self.global_port, token, h_tokens)
            webhook_url = self.slack_kargs['slack_webhook']
            payload = self.get_slack_kargs()
            payload['text'] = message
            self.execute_post(webhook_url, payload)
            # requests.post(webhook_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})

    async def collector_notify(self, sensor_id, sensor_ip, token, dt, now, results):
        if self.mongo_kargs['mongo']:
            try:
                await self.ping_sensor(sensor_id, sensor_ip, token, dt, now)
                await self.add_mongo_results(results)
            except:
                self.LOGGER.info("Failed to connect to and log results to mongo.")
                self.LOGGER.error("{}".format(traceback.format_exc()))

        if self.slack_kargs['slack']:
            try:
                await self.send_slack_notifications(results)
            except:
                self.LOGGER.info("Failed to connect to and log results to slack.")
                self.LOGGER.error("{}".format(traceback.format_exc()))

        if self.wbx_kargs['wbx']:
            try:
                await self.send_wbx_teams_notifications(results)
            except:
                self.LOGGER.info("Failed to connect to and log results to Webex Teams.")
                self.LOGGER.error("{}".format(traceback.format_exc()))

        await self.stdout(results)

    async def notify(self, results):
        if self.mongo_kargs['mongo']:
            try:
                await self.add_mongo_results(results)
            except:
                self.LOGGER.info("Failed to connect to and log results to mongo.")
                self.LOGGER.error("{}".format(traceback.format_exc()))

        if self.slack_kargs['slack']:
            try:
                await self.send_slack_notifications(results)
            except:
                self.LOGGER.info("Failed to connect to and log results to slack.")
                self.LOGGER.error("{}".format(traceback.format_exc()))

        if self.wbx_kargs['wbx']:
            try:
                await self.send_wbx_teams_notifications(results)
            except:
                self.LOGGER.info("Failed to connect to and log results to Webex Teams.")
                self.LOGGER.error("{}".format(traceback.format_exc()))

        if self.collector_kargs['collector']:
            try:
                await self.send_http_notifications(results)
            except:
                self.LOGGER.info("Failed to connect to and log results to HTTP endpoint.")
                self.LOGGER.error("{}".format(traceback.format_exc()))

        await self.stdout(results)
    
    async def stdout(self, results):
        for result in results:
            if result['rtype'] == CREATE and result['request_data']:
                kargs = result.copy()
                r = result['request_data'].get('Cmd', [])
                kargs['command'] = " ".join(r)
                kargs['image'] = result['request_data'].get('Image', [])
                self.LOGGER.info("{src_ip}:{src_port} creating image:{image} '''{command}'''".format(**kargs))

    async def log_register(self, sensor_name, sensor_ip, token):
        message = "{} ({}) registered with {}".format(sensor_name, sensor_ip, token)
        self.LOGGER.info(message)        
        if self.wbx_kargs['wbx']:
            webhook_url = self.wbx_kargs['wbx_webhook']
            requests.post(webhook_url, data=json.dumps({'markdown': message}), headers={'Content-Type': 'application/json'})

        if self.slack_kargs['slack']:
            webhook_url = self.slack_kargs['slack_webhook']
            payload = self.get_slack_kargs()
            payload['text'] = message
            requests.post(webhook_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})

    async def log_ping(self, sensor_name, sensor_ip, token):
        message = "{} ({}) pinged with {}".format(sensor_name, sensor_ip, token)
        self.LOGGER.info(message)        
        # if self.wbx_kargs['wbx']:
        #     webhook_url = self.wbx_kargs['wbx_webhook']
        #     requests.post(webhook_url, data=json.dumps({'markdown': message}), headers={'Content-Type': 'application/json'})

        # if self.slack_kargs['slack']:
        #     webhook_url = self.slack_kargs['slack_webhook']
        #     payload = self.get_slack_kargs()
        #     payload['text'] = message
        #     requests.post(webhook_url, data=json.dumps({'markdown': message}), headers={'Content-Type': 'application/json'})

    async def log_new_token(self, email, name, is_admin):
        message = "Token created: ({}) {} {}".format(email, name, is_admin)
        self.LOGGER.info(message)        

    async def get_sensor(self, sensor_id):
        try:
            sensors = RegisteredSensor.objects(sensor_id=sensor_id)
            if len(sensors) > 0:
                return sensors[0]
        except:
            self.LOGGER.error("Failed to get sensor info:\n{}".format(traceback.format_exc()))
        return None

    async def register_sensor(self, sensor_id, sensor_ip, token, dt, now):
        rs = await self.get_sensor(sensor_id) if self.mongo_kargs['mongo'] else None
        if rs:
            rs.last_ping = now
            rs.save()
            return True
        rs = RegisteredSensor(sensor_id=sensor_id, sensor_ip=sensor_ip, token=token, 
                              created_at=now, received_at=now, last_ping=dt)
        await self.log_register(sensor_id, sensor_ip, token)
        if self.mongo_kargs['mongo']:
            try:
                rs.save()
                return True
            except:
                self.LOGGER.error("Failed to save sensor register info:\n{}".format(traceback.format_exc()))

    async def get_request_result(self, result_id):
        try:
            info = RequestResultEvent.objects(result_id=result_id)
            if len(info) > 0:
                return info[0]
        except:
            self.LOGGER.error("Failed to get request result:\n{}".format(traceback.format_exc()))
        return None

    async def get_event(self, result_id):
        try:
            info = GeneralEvent.objects(event_id=result_id)
            if len(info) > 0:
                return info[0]
        except:
            self.LOGGER.error("Failed to get event info:\n{}".format(traceback.format_exc()))

        return None

    async def requests_sensor(self, sensor_id, sensor_ip, token, dt, now, payload):
        self.LOGGER.info("Updating last sensor_info ({}) ping: {}".format(sensor_id, dt))
        try:
            sensor_info = await self.get_sensor(sensor_id) if self.mongo_kargs['mongo'] else None
            if sensor_info:
                sensor_info.last_ping = now
                sensor_info.save()
        except:
            self.LOGGER.info("Failed to update sensor_info ({}): {}".format(sensor_id, traceback.format_exc()))

        command = payload.get(COMMAND, None)
        request_parameters = payload.get(REQUEST_PARAMETERS, {})
        response_info = payload.get(RESPONSE_INFO, {})
        result_id = create_token(iters=1)
        orm_kargs = {}
        orm_kargs['sensor_id'] = sensor_id
        orm_kargs['sensor_ip'] = sensor_ip
        orm_kargs['created_at'] = dt
        orm_kargs['received_at'] = now
        orm_kargs['response_info'] = response_info
        orm_kargs['request_parameters'] = request_parameters
        orm_kargs['result_id'] = result_id

        result = RequestResultEvent(**orm_kargs)
        self.LOGGER.info("Saving event result to mongodb for ({})".format(sensor_id))
        if self.mongo_kargs['mongo']:
            try:
                result.save()
            except:
                self.LOGGER.error("Failed to request result event:\n{}".format(traceback.format_exc()))

        # notify via webx ?
        self.LOGGER.info("Notifying webex teams for ({})".format(sensor_id))
        dl_kargs = {'host': self.global_hostname, 
                    'port': self.global_port,
                    'result_id': result_id}
        url = request_parameters.get(URL, None)

        link = DOWNLOAD_LINK.format(**dl_kargs)
        summary_link = SUMMARY_LINK.format(**dl_kargs)
        msg_kargs = {'sensor_id': sensor_id,
                 'sensor_ip': sensor_ip,
                 'download_link': link,
                 'summary_link': summary_link,
                 'url': url}
        
        wbx = self.wbx_kargs['wbx']
        slack = self.slack_kargs['slack']
        self.LOGGER.info("Loging results to wbx_webhook: {}".format(wbx))
        
        if wbx:
            webhook_url = self.wbx_kargs['wbx_webhook']
            message = WBX_DOWNLOAD_MESSAGE.format(**msg_kargs)
            if payload and self.execute_post(webhook_url, {'markdown': message}):
                self.LOGGER.info("[+] Success, logging results to slack".format())
            else:
                self.LOGGER.info("[X] Failed, logging results to slack".format())
        
        if slack:
            webhook_url = self.slack_kargs['slack_webhook']
            message = SLACK_DOWNLOAD_MESSAGE.format(**msg_kargs)
            payload['text'] = "Alert: docker create"
            blocks = [
                {            
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": message
                    }
                }
            ]
            payload['blocks'] = blocks
            if payload and self.execute_post(webhook_url, payload):
                self.LOGGER.info("[+] Success, logging results to slack".format())
            else:
                self.LOGGER.info("[X] Failed, logging results to slack".format())

    async def submit_remote_requests(self, sensor_id, sensor_ip, port, payload):
        now = get_iso_time()
        url = "https://{}:{}".format(sensor_ip, port) + PING_ENDPOINT
        verify = False        
        cert=None
        payload[TOKEN] = self.server_secret_key
        if not self.execute_post(url, payload):
            collector_url = self.get_collector_url(use_alt=True) + PING_ENDPOINT
            self.execute_post(collector_url, payload)

    async def ping_sensor(self, sensor_id, sensor_ip, token, dt, now):
        sensor = await self.get_sensor(sensor_id) if self.mongo_kargs['mongo'] else None
        if sensor:
            sensor.last_ping = now
            sensor.save()
        elif self.mongo_kargs['mongo']:
            await self.register_sensor(sensor_id, sensor_ip, token, dt, now)

        rs = PingSensor(sensor_id=sensor_id, sensor_ip=sensor_ip, token=token, created_at=dt, received_at=now)
        await self.log_ping(sensor_id, sensor_ip, token)
        if self.mongo_kargs['mongo']:
            try:
                rs.save()
            except:
                self.LOGGER.error("Failed to save sensor info:\n{}".format(traceback.format_exc()))

    def get_sensor_infos(self, sensor_ip=None, sensor_id=None, token=None):
        kargs = {}
        if sensor_ip:
            kargs['sensor_ip'] = sensor_ip
        if sensor_id:
            kargs['sensor_id'] = sensor_id
        if token:
            kargs['token'] = token

        try:
            objs = RegisteredSensor.objects(**kargs)
            return objs
        except:
            traceback.print_exc()
        return []        

    async def get_token(self, token_value):
        try:
            objs = TokenInfo.objects(token=token_value)
            if len(objs) > 0:
                return objs[0]
            return None
        except:
            self.LOGGER.error("Failed to get token: {}".format(traceback.format_exc()))

    async def get_first_token(self):
        try:
            objs = TokenInfo.objects(creator_token=FIRSTIES_TOKEN)
            if len(objs) > 0:
                return objs[0]
            return None
        except:
            self.LOGGER.error("Failed to find expected first token:\n{}".format(traceback.format_exc()))
            raise


    async def touch_token(self, token, now):
        if not self.mongo_kargs['mongo']:
            return False

        token_info = await self.get_token(token)
        if token_info is None:
            return False
        token_info.modified_at = now
        try:
            token_info.save()
        except:
            self.LOGGER.error("Failed to touch token:\n{}".format(traceback.format_exc()))
            return False
        return True

    async def is_admin(self, token, token_info=None):
        if not token_info is None:
            return token_info.is_admin

        token_info = await self.get_token(token)
        if token_info is None:
            return None
        return token_info.is_admin

    async def is_active(self, token, token_info=None):
        if not token_info is None:
            return token_info.is_active

        token_info = await self.get_token(token)
        if token_info is None:
            return None
        return token_info.is_active

    async def is_valid(self, token):
        ti = await self.get_token(token)
        return not ti is None

    async def new_token(self, creator_token, email='', name='', description='', is_admin=False, is_active=True):
        if not self.is_admin(creator_token):
            return None
        token = create_token()
        now = get_iso_time()
        token_info = await self.add_token(creator_token, token, email, name, description, is_admin, is_active, now, now, now)
        await self.log_new_token(email, name, is_admin)
        return token_info

    async def create_first_admin(self, email='', name='', description=''):
        creator_token = await self.get_first_token()
        if creator_token is not None:
            raise Exception("There can be only 1!")
        token = create_token()
        now = get_iso_time()
        token_info = await self.add_token(FIRSTIES_TOKEN, token, email, name, description, True, True, now, now, now)
        await self.log_new_token(email, name, False)
        return token_info

    async def get_honeypot_token_values(self):
        try:
            objs = TokenInfo.objects(name=HONEYPOT_TOKEN)
            tokens =  [i.token for i in objs]
        except:
            self.LOGGER.error("Failed to get honeypot tokens:\n{}".format(traceback.format_exc()))
            raise


    async def create_honeypot_token(self, email=None, name=None, description=None):
        creator_token_info = await self.get_first_token()
        if creator_token_info is None:
            creator_token_info = await self.create_first_admin()

        email = email if email is not None else creator_token_info.email
        name = HONEYPOT_TOKEN
        description = HONEYPOT_DESCRIPTION
        token = create_token()
        now = get_iso_time()
        token_info = await self.add_token(creator_token_info.token, token, email, name, description, False, True, now, now, now)
        await self.log_new_token(email, name, False)
        return token_info

    async def add_token(self, creator_token, token, email, name, description, is_admin, is_active, created_at=None, modified_at=None, last_used=None):
        kargs = {
            "creator_token":creator_token, 
            "token":token, 
            "email":email, 
            "name":name, 
            "description":description, 
            "is_admin":is_admin, 
            "is_active":is_active, 
            "created_at":get_iso_time() if created_at is None else created_at, 
            "modified_at":get_iso_time() if modified_at is None else modified_at, 
            "last_used":get_iso_time() if last_used is None else last_used, 
        }
        rs = TokenInfo(**kargs)
        if self.mongo_kargs['mongo']:
            try:
                rs.save()
            except:
                self.LOGGER.error("Failed to save token info:\n{}".format(traceback.format_exc()))
        return rs

    def get_collector_url(self, use_alt=False):
        host = None
        port = None
        if use_alt:
            host = self.collector_kargs.get('collector_alt_host', None)
            port = self.collector_kargs.get('collector_alt_port', None)


        if host is None and self.collector_kargs.get('collector_host', None) is None:
            host = DEFAULT_COLLECTOR_HOST
        elif host is None:
            host = self.collector_kargs.get('collector_host', None)
        

        if port is None and self.collector_kargs.get('collector_port', None) is None:
            port = DEFAULT_COLLECTOR_PORT
        elif port is None:
            port = self.collector_kargs.get('collector_port', None)

        kargs = {'collector_port': port,'collector_host': host,}
        return self.collector_kargs['collector_url_fmt'].format(**kargs)

    def execute_post(self, collector_url, payload, verify=False):
        rsp = None
        host = collector_url.split("://")[1].split("/")[0]
        try:
            rsp = requests.post(collector_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'},
                          verify=verify)
        except:
            self.LOGGER.info("Failed to connect to {}.".format(host))
            self.LOGGER.error("{}".format(traceback.format_exc()))

        finally:
            if rsp:
                self.LOGGER.info("Connected to {} with response:{}.".format(host, rsp.status_code))
            if rsp and (rsp.status_code >= 200 and rsp.status_code <= 299):
                return True
        return False

    def prune_processes(self):
        self.PROCESSES = [p for p in self.PROCESSES if p.is_alive()]

    async def send_ping(self):
        self.prune_processes()
        if not self.collector_kargs['collector']:
            return
        now = get_iso_time()
        collector_url = self.get_collector_url() + PING_ENDPOINT
        verify = False
        if self.collector_kargs['collector_verify_ssl'] and self.collector_kargs['collector_server_crt']:
            verify = self.collector_kargs['collector_server_crt']
        
        cert=None

        payload = self.get_base_payload()
        
        if not self.execute_post(collector_url, payload):
            collector_url = self.get_collector_url(use_alt=True) + PING_ENDPOINT
            self.execute_post(collector_url, payload)

    async def send_registration(self):
        if not self.collector_kargs['collector']:
            return
        now = get_iso_time()
        collector_url = self.get_collector_url() + REGISTER_ENDPOINT
        verify = False
        if self.collector_kargs['collector_verify_ssl'] and self.collector_kargs['collector_server_crt']:
            verify = self.collector_kargs['collector_server_crt']
        
        cert=None
        try:
            payload = self.get_base_payload()
        except:
            self.LOGGER.error("Failed to get base payload:\n{}".format(traceback.format_exc()))

        if not self.execute_post(collector_url, payload):
            collector_url = self.get_collector_url(use_alt=True) + REGISTER_ENDPOINT
            self.execute_post(collector_url, payload)

    async def send_http_notifications(self, results):
        self.LOGGER.info("Logging {} events to http endpoint".format(len(results)))
        if not self.collector_kargs['collector']:
            return

        collector_url = self.get_collector_url() + EVENTS_ENDPOINT
        verify = False
        if self.collector_kargs['collector_verify_ssl'] and self.collector_kargs['collector_server_crt']:
            verify = self.collector_kargs['collector_server_crt']
        
        cert=None
        payload = self.get_base_payload()
        payload[EVENTS] = results
        if not self.execute_post(collector_url, payload):
            collector_url = self.get_collector_url(use_alt=True) + EVENTS_ENDPOINT
            self.execute_post(collector_url, payload)

    async def add_mongo_results(self, results):

        for result in results:
            # not all results have requests in them
            result['request'] = result.get('request', '')
            gr = GeneralEvent(**result)
            if self.mongo_kargs['mongo']:
                try:
                    gr.save()
                except:
                    self.LOGGER.error("Failed to save GeneralEvent:\n{}".format(traceback.format_exc()))
                    raise
            ce = None
            if gr.rtype == CREATE and gr.request_data:
                kargs = {}
                Cmd = gr.request_data.get('Cmd', [])
                kargs['command'] = ' '.join(Cmd)
                kargs['image'] = gr.request_data.get('Image', [])
                kargs['event_id'] = gr.event_id 
                for k in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'created_at']:
                    kargs[k] = result[k]
                ce = CreateEvent(**kargs)
            
            if self.mongo_kargs['mongo']:
                if ce:
                    try:
                        ce.save()
                    except:
                        self.LOGGER.error("Failed to save event info:\n{}".format(traceback.format_exc()))

    @classmethod
    async def add_elk_results(cls, results):
        # add results to elk from here
        pass


    def get_slack_kargs(self):
        slack_kargs = {}
        slack_kargs["channel"] = self.slack_kargs.get("slack_channel", None)
        slack_kargs["username"] = self.slack_kargs.get("slack_username", None)
        # slack_kargs["webhook"] = self.slack_kargs.get("slack_webhook", None)
        slack_kargs["icon_emoji"] = self.slack_kargs.get("slack_emoticon", ":suspect:")
        return slack_kargs


    async def send_slack_notifications(self, results):
        payload = self.get_slack_kargs()
        webhook_url = self.slack_kargs['slack_webhook'] 
        using_slack = self.slack_kargs['slack']
        # self.LOGGER.info("Loging results to slack: {}".format(using_slack))
        if not using_slack:
            return

        for result in results:
            payload = self.get_slack_kargs()
            token = self.admin_token
            if result['rtype'] == CREATE and result['request_data']:
                kargs = result.copy()
                r = result['request_data'].get('Cmd', [])
                kargs['command'] = " ".join(r)
                kargs['image'] = result['request_data'].get('Image', [])
                kargs['dst_ip'] = kargs['dst_ip']
                kargs['trigger_collector'] = ''
                event_id = result.get(EVENT_ID, -1)
                if self.is_collector:
                    kargs['trigger_collector'] = "\n\n6. *Collector web request:* https://{}:{}/remote_web_request".format(self.global_hostname, self.global_port)
                    if isinstance(event_id, str) and len(event_id) > 0:
                        fmt_args = (self.global_hostname, self.global_port, token, event_id, self.server_secret_key)
                        kargs['trigger_collector'] = kargs['trigger_collector'] + "\n\n7. *Event JSON:* https://{}:{}/event/{}/{}\n\n".format(*fmt_args)


                # message = ("{src_ip}:{src_port} => {dst_ip}:{dst_port} creating docker image:{image} for \'\'\'{command}\'\'\'".format(**kargs))
                message = ("1. *Attempting to create an contianer on {sensor_id} ({sensor_ip}) for API: {api}* \n2. Source: *{src_ip}:{src_port}* \n3. Destination: *{dst_ip}:{dst_port}*\n4. Image: *{image}*\n5. Command: `{command}`{trigger_collector}".format(**kargs))
                payload['text'] = "Alert: docker create"
                blocks = [
                    {            
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": message
                        }
                    }
                ]
                payload['blocks'] = blocks

            elif result['rtype'] == GET_VERSION:
                kargs = result.copy()
                kargs['dst_ip'] = kargs['dst_ip']
                message = ("1. *Attempting recon of {sensor_id} ({sensor_ip}) for API: {api}* \n2. Source: *{src_ip}:{src_port}*\n3. Destination: *{dst_ip}:{dst_port}*".format(**kargs))
                payload['text'] = "Alert: docker recon"
                blocks = [
                    {            
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": message
                        }
                    }
                ]
                payload['blocks'] = blocks

            if payload and self.execute_post(webhook_url, payload):
                self.LOGGER.info("[+] Success, logging results to slack".format())
            else:
                self.LOGGER.info("[X] Failed, logging results to slack".format())


    def update_wbx_config(self, dargs):
        self.wbx_kargs['wbx_webhook'] = dargs.get('wbx_webhook', None)
        self.wbx_kargs['wbx'] = dargs.get('wbx', False) and dargs.get('wbx_webhook', None) is not None

    async def send_wbx_teams_notifications(self, results):
        webhook_url = self.wbx_kargs['wbx_webhook']
        wbx = self.wbx_kargs['wbx']
        self.LOGGER.info("Loging results to wbx_webhook: {}".format(wbx))
        if wbx is None:
            return

        for result in results:
            payload = None
            token = self.admin_token
            if result['rtype'] == CREATE and result['request_data']:
                kargs = result.copy()
                r = result['request_data'].get('Cmd', [])
                event_id = result.get('event_id', None)
                kargs['command'] = " ".join(r)
                kargs['image'] = result['request_data'].get('Image', [])
                kargs['dst_ip'] = kargs['dst_ip']
                kargs['trigger_collector'] = ''
                if self.is_collector:
                    kargs['trigger_collector'] = "\n\n6. **Collector web request:** https://{}:{}/remote_web_request\n\n".format(self.global_hostname, self.global_port)
                    if isinstance(event_id, str) and len(event_id) > 0:
                        fmt_args = (self.global_hostname, self.global_port, token, event_id, self.server_secret_key)
                        kargs['trigger_collector'] = kargs['trigger_collector'] + "\n\n7. **Event JSON:** https://{}:{}/event/{}/{}\n\n".format(*fmt_args)
                message = ("1. **Attempting to create an image on **{sensor_id} ({sensor_ip})** for API: {api}** \n2. **Source:** {src_ip}:{src_port} \n3. **Destination:** {dst_ip}:{dst_port}\n4. **Image:** {image}\n5. **Command:** `{command}`{trigger_collector}".format(**kargs))
                # self.LOGGER.info("Sending results {} to wbx_webhook".format(result['rtype']))
                payload = {'markdown': message}
            elif result['rtype'] == GET_VERSION:
                kargs = result.copy()
                kargs['dst_ip'] = self.sensor_ip if self.sensor_ip else kargs['dst_ip']
                message = ("1. **Attempting recon for **{sensor_id} ({sensor_ip})** API:** {api}\n2. **Source:** {src_ip}:{src_port}\n3. **Destination:** {dst_ip}:{dst_port}".format(**kargs))
                # self.LOGGER.info("Sending results {} to wbx_webhook".format(result['rtype']))
                payload = {'markdown': message}
            
            if payload and self.execute_post(webhook_url, payload):
                self.LOGGER.info("[+] Success, logging results to wbx".format())
            else:
                self.LOGGER.info("[X] Failed, logging results to wbx".format())

    async def send_request_results(self, response_payload: dict):
        http_url = self.collector_kargs['collector_url'].strip("/") + REQUESTS_ENDPOINT
        verify = False
        if self.collector_kargs['collector_verify_ssl'] and self.collector_kargs['collector_server_crt']:
            verify = self.collector_kargs['collector_server_crt']

        payload = self.get_base_payload()
        payload.update(request_results)
        requests.post(http_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'},
                      verify=verify, cert=cert)

    def start_process_commands(self, sensor_id, sensor_ip, token, payload):
        self.LOGGER.info("Starting process to handle remote command".format())
        p = Process(target=self.handle_incoming_commands, 
                    args=(sensor_id, sensor_ip, token, payload))
        p.start()
        self.PROCESSES.append(p)

    def handle_incoming_commands(self, sensor_id, sensor_ip, token, payload):
        async def doit():
            response = await CommandHandler.handle_commands(**payload)
            collector_url = self.get_collector_url() + COMMANDS_RESPONSE_ENDPOINT
            verify = False
            cert=None
            response.update(self.get_base_payload())
            if not self.execute_post(collector_url, response):
                collector_url = self.get_collector_url(use_alt=True) + COMMANDS_RESPONSE_ENDPOINT
                self.execute_post(collector_url, response)
        asyncio.run(doit())
