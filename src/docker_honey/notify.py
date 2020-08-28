import traceback
import requests
import json
import urllib
from .consts import *
from .mongo_orm import GeneralEvent, CreateEvent

class Notifier(object):
    def __init__(self, sensor_id=DEFAULT_SENSOR_NAME, sensor_ip=SENSOR_EXT_IP, **kargs):
        self.sensor_id = sensor_id
        self.sensor_ip = sensor_ip
        
        self.slack_kargs = {}
        self.http_kargs = {}
        self.mongo_kargs = {}
        self.wbx_kargs = {}
        self.email_kargs = {}
        self.elk_kargs = {}

        self.mongo_kargs['using_mongo'] = False
        self.slack_kargs['using_slack'] = False
        self.wbx_kargs['using_wbx'] = False
        self.email_kargs['using_email'] = False
        self.elk_kargs['using_elk'] = False

        self.update_http_config(kargs)
        self.update_wbx_config(kargs)
        self.update_slack_config(kargs)
        self.update_mongo_config(kargs)
        self.update_email_config(kargs)

    async def collector_notify(self, results):
        if self.mongo_kargs['using_mongo']:
            try:
                await self.add_mongo_results(results)
            except:
                DOCKER_HP_LOGGER.info("Failed to connect to and log results to mongo.")
        if self.elk_kargs['using_elk']:
            try:
                await self.add_elk_results(results)
            except:
                DOCKER_HP_LOGGER.info("Failed to connect to and log results to elk.")
        if self.slack_kargs['using_slack']:
            try:
                await self.send_slack_notifications(results)
            except:
                DOCKER_HP_LOGGER.info("Failed to connect to and log results to slack.")
        if self.wbx_kargs['using_wbx']:
            try:
                await self.send_wbx_teams_notifications(results)
            except:
                DOCKER_HP_LOGGER.info("Failed to connect to and log results to Webex Teams.")

        await self.stdout(results)

    async def notify(self, results):
        if self.mongo_kargs['using_mongo']:
            try:
                await self.add_mongo_results(results)
            except:
                DOCKER_HP_LOGGER.info("Failed to connect to and log results to mongo.")
        if self.elk_kargs['using_elk']:
            try:
                await self.add_elk_results(results)
            except:
                DOCKER_HP_LOGGER.info("Failed to connect to and log results to elk.")
        if self.slack_kargs['using_slack']:
            try:
                await self.send_slack_notifications(results)
            except:
                DOCKER_HP_LOGGER.info("Failed to connect to and log results to slack.")
        if self.wbx_kargs['using_wbx']:
            try:
                await self.send_wbx_teams_notifications(results)
            except:
                DOCKER_HP_LOGGER.info("Failed to connect to and log results to Webex Teams.")

        if self.http_kargs['using_http']:
            try:
                await self.send_http_notifications(results)
            except:
                traceback.print_exc()
                DOCKER_HP_LOGGER.info("Failed to connect to and log results to HTTP endpoint.")

        await self.stdout(results)
    
    async def stdout(self, results):
        for result in results:
            if result['rtype'] == CREATE and result['request_data']:
                kargs = result.copy()
                r = result['request_data'].get('Cmd', [])
                kargs['command'] = " ".join(r)
                kargs['image'] = result['request_data'].get('Image', [])
                DOCKER_HP_LOGGER.info("{src_ip}:{src_port} creating image:{image} '''{command}'''".format(**kargs))

    async def log_register(self, sensor_name, sensor_ip, token):
        message = "{} ({}) registered with {}".format(sensor_name, sensor_ip, token)
        DOCKER_HP_LOGGER.info(message)        
        if self.wbx_kargs['using_wbx']:
            webhook_url = self.wbx_kargs['webhook']
            requests.post(webhook_url, data=json.dumps({'markdown': message}), headers={'Content-Type': 'application/json'})

        if self.slack_kargs['using_slack']:
            webhook_url = self.slack_kargs['webhook']
            payload = {k:self.slack_kargs[k] for k in self.webhook_payload}
            payload['text'] = message
            requests.post(webhook_url, data=json.dumps({'markdown': message}), headers={'Content-Type': 'application/json'})

    async def log_ping(self, sensor_name, sensor_ip, token):
        message = "{} ({}) {}:{} pinged with {}".format(sensor_name, sensor_ip, token)
        DOCKER_HP_LOGGER.info(message)        
        if self.wbx_kargs['using_wbx']:
            webhook_url = self.wbx_kargs['webhook']
            requests.post(webhook_url, data=json.dumps({'markdown': message}), headers={'Content-Type': 'application/json'})

        if self.slack_kargs['using_slack']:
            webhook_url = self.slack_kargs['webhook']
            payload = {k:self.slack_kargs[k] for k in self.webhook_payload}
            payload['text'] = message
            requests.post(webhook_url, data=json.dumps({'markdown': message}), headers={'Content-Type': 'application/json'})

    async def register_sensor(sensor_id, sensor_ip, token, dt, now):
        rs = RegisterSensor(sensor_id, sensor_ip, token, dt, now)
        await self.log_register(sensor_id, sensor_ip, token)
        if USING_MONGO:
            try:
                rs.save()
            except:
                pass

    async def ping_sensor(sensor_id, sensor_ip, token, dt, now):
        rs = PingSensor(sensor_id, sensor_ip, token, dt, now)
        await self.log_ping(sensor_id, sensor_ip, token)
        if USING_MONGO:
            try:
                rs.save()
            except:
                pass

    def update_http_config(self, dargs):
        self.http_kargs['using_http'] = dargs.get('http', False)
        self.http_kargs['http_verify_ssl'] = dargs.get('http_verify_ssl', False)
        self.http_kargs["http_client_key"] = dargs.get("http_client_key", None)
        self.http_kargs["http_client_crt"] = dargs.get("http_client_crt", None)
        self.http_kargs["http_server_crt"] = dargs.get("http_server_crt", None)
        self.http_kargs["http_url"] = dargs.get("http_url", None)
        self.http_kargs["http_token"] = dargs.get("http_token", None)
        x = urllib.parse.urlparse(self.http_kargs["http_url"])
        base_url = "{scheme}://{netloc}".format(**x._asdict())
        if self.http_kargs["http_url"] is None:
            self.http_kargs["using_http"] = False 

        self.http_kargs["http_registration_url"] = dargs.get("http_registration_url", None)
        if self.http_kargs['using_http'] and self.http_kargs["http_registration_url"] is None:
            self.http_kargs["http_registration_url"] = base_url + REGISTER_PATH

        self.http_kargs["http_ping_url"] = dargs.get("http_ping_url", None)
        if self.http_kargs['using_http'] and self.http_kargs["http_ping_url"] is None:
            self.http_kargs["http_registration_url"] = base_url + PING_PATH 

    async def send_ping(self):
        now = get_iso_time()
        http_url = self.http_kargs['http_ping_url']
        verify = False
        if self.http_kargs['http_verify_ssl'] and self.http_kargs['http_server_crt']:
            verify = self.http_kargs['http_server_crt']
        
        cert=None
        if self.http_kargs['http_client_key'] and self.http_kargs['http_client_crt']:
            cert = (self.http_kargs['http_client_crt'], self.http_kargs['http_client_key'])

        payload = {TOKEN: self.http_kargs['http_token'], 
                   SENSOR_ID: self.sensor_id, 
                   SENSOR_IP: self.sensor_ip}

        requests.post(http_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'},
                      verify=verify, cert=cert)

    async def send_registration(self):
        now = get_iso_time()
        http_url = self.http_kargs['http_registration_url']
        verify = False
        if self.http_kargs['http_verify_ssl'] and self.http_kargs['http_server_crt']:
            verify = self.http_kargs['http_server_crt']
        
        cert=None
        if self.http_kargs['http_client_key'] and self.http_kargs['http_client_crt']:
            cert = (self.http_kargs['http_client_crt'], self.http_kargs['http_client_key'])

        payload = {TOKEN: self.http_kargs['http_token'], 
                   SENSOR_ID: self.sensor_id, 
                   SENSOR_IP: self.sensor_ip}

        requests.post(http_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'},
                      verify=verify, cert=cert)

    async def send_http_notifications(self, results):
        DOCKER_HP_LOGGER.info("Logging {} events to http endpoint".format(len(results)))
        if not self.http_kargs['using_http']:
            return

        http_url = self.http_kargs['http_url']
        verify = False
        if self.http_kargs['http_verify_ssl'] and self.http_kargs['http_server_crt']:
            verify = self.http_kargs['http_server_crt']
        
        cert=None
        if self.http_kargs['http_client_key'] and self.http_kargs['http_client_crt']:
            cert = (self.http_kargs['http_client_crt'], self.http_kargs['http_client_key'])

        payload = {TOKEN: self.http_kargs['http_token'], 
                   SENSOR_ID: self.sensor_id, 
                   SENSOR_IP: self.sensor_ip,
                   EVENTS: results}

        requests.post(http_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'},
                      verify=verify, cert=cert)

    def update_mongo_config(self, dargs):
        self.mongo_kargs['using_mongo'] = dargs.get('mongo', False)
        self.mongo_kargs['hostname'] = dargs.get('mongo_host', '127.0.0.1')
        self.mongo_kargs['port'] = dargs.get('mongo_port', 27017)
        self.mongo_kargs['username'] = dargs.get('mongo_user', None)
        self.mongo_kargs['password'] = dargs.get('mongo_pass', None)
        self.mongo_kargs['database'] = dargs.get('mongo_db', 'docker-honeypot')

        if self.mongo_kargs['using_mongo']:
            connect(host=self.mongo_kargs['hostname'], 
                    port=self.mongo_kargs['port'],
                    db=self.mongo_kargs['database'],
                    username=self.mongo_kargs['username'],
                    password=self.mongo_kargs['password'])
        
    @classmethod
    async def add_mongo_results(cls, results):

        for result in results:
            gr = GeneralEvent(**result)
            ce = None
            if gr.rtype == CREATE and gr.request_data:
                kargs = {}
                Cmd = gr.request_data.get('Cmd', [])
                kargs['command'] = ' '.join(Cmd)
                kargs['image'] = gr.request_data.get('Image', [])
                for k in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'created_at']:
                    kargs[k] = result[k]
                ce = CreateEvent(**kargs)
            
            if USING_MONGO:
                try:
                    gr.save()
                except:
                    pass
                if ce:
                    try:
                        ce.save()
                    except:
                        pass

    @classmethod
    async def add_elk_results(cls, results):
        # add results to elk from here
        pass

    def update_slack_config(self, dargs):
        self.slack_kargs['using_slack'] = dargs.get('slack', False)
        self.slack_kargs["channel"] = dargs.get("slack_channel", None)
        self.slack_kargs["username"] = dargs.get("slack_username", None)
        self.slack_kargs["webhook"] = dargs.get("slack_webhook", None)
        self.slack_kargs["icon_emoji"] = dargs.get("slack_emoticon", ":suspect:")
        self.webhook_payload = ['channel', 'username', 'icon_emoji']


    async def send_slack_notifications(self, results):
        payload = {k:self.slack_kargs[k] for k in self.webhook_payload}
        webhook_url = self.slack_kargs['webhook'] 
        using_slack = self.slack_kargs['using_slack']
        DOCKER_HP_LOGGER.info("Loging results to slack: {}".format(using_slack))
        if not using_slack:
            return

        for result in results:
            if result['rtype'] == CREATE and result['request_data']:
                kargs = result.copy()
                r = result['request_data'].get('Cmd', [])
                kargs['command'] = " ".join(r)
                kargs['image'] = result['request_data'].get('Image', [])
                kargs['dst_ip'] = kargs['dst_ip']
                # message = ("{src_ip}:{src_port} => {dst_ip}:{dst_port} creating docker image:{image} for \'\'\'{command}\'\'\'".format(**kargs))
                message = ("1. *Attempting to create an contianer on {sensor_id} ({sensor_ip}) for API: {api}* \n2. Source: *{src_ip}:{src_port}* \n3. Destination: *{dst_ip}:{dst_port}*\n4. Image: *{image}*\n5. Command: `{command}`".format(**kargs))
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
                requests.post(webhook_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})

            elif result['rtype'] == GET_VERSION:
                kargs = result.copy()
                kargs['dst_ip'] = kargs['dst_ip']
                message = ("1. *Attempting recon of {sensor_id} ({sensor_ip}) for API: {api}* \n2. Source: *{src_ip}:{src_port}*\n3. Destination: *{dst_ip}:{dst_port}*".format(**kargs))
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
                requests.post(webhook_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})

    def update_wbx_config(self, dargs):
        self.wbx_kargs['webhook'] = dargs.get('wbx_webhook', None)
        self.wbx_kargs['using_wbx'] = dargs.get('wbx', False) and dargs.get('wbx_webhook', None) is not None

    async def send_wbx_teams_notifications(self, results):
        webhook_url = self.wbx_kargs['webhook']
        using_wbx = self.wbx_kargs['using_wbx']
        DOCKER_HP_LOGGER.info("Loging results to wbx_webhook: {}".format(using_wbx))
        if using_wbx is None:
            return

        for result in results:
            if result['rtype'] == CREATE and result['request_data']:
                kargs = result.copy()
                r = result['request_data'].get('Cmd', [])
                kargs['command'] = " ".join(r)
                kargs['image'] = result['request_data'].get('Image', [])
                kargs['dst_ip'] = kargs['dst_ip']
                message = ("1. **Attempting to create an image on **{sensor_id} ({sensor_ip})** for API: {api}** \n2. **Source:** {src_ip}:{src_port} \n3. **Destination:** {dst_ip}:{dst_port}\n4. **Image:** {image}\n5. **Command:** `{command}`".format(**kargs))
                # DOCKER_HP_LOGGER.info("Sending results {} to wbx_webhook".format(result['rtype']))
                requests.post(webhook_url, data=json.dumps({'markdown': message}), headers={'Content-Type': 'application/json'})
            elif result['rtype'] == GET_VERSION:
                kargs = result.copy()
                kargs['dst_ip'] = self.sensor_ip if self.sensor_ip else kargs['dst_ip']
                message = ("1. **Attempting recon for **{sensor_id} ({sensor_ip})** API:** {api}\n2. **Source:** {src_ip}:{src_port}\n3. **Destination:** {dst_ip}:{dst_port}".format(**kargs))
                # DOCKER_HP_LOGGER.info("Sending results {} to wbx_webhook".format(result['rtype']))
                requests.post(webhook_url, data=json.dumps({'markdown': message}), headers={'Content-Type': 'application/json'})

    def update_email_config(self, dargs):
        self.email_kargs["username"] = dargs.get("email_username", None)
        self.email_kargs["password"] = dargs.get("email_password", None)
        self.email_kargs["server"] = dargs.get("email_server", None)
        self.email_kargs["port"] = dargs.get("email_port", None)
        self.email_kargs["cc_list"] = dargs.get("email_cc_list", None)
        self.email_kargs["subject"] = dargs.get('email_notify_subject', None)

        can_doit = True
        for k in ['server', 'port', 'cc_list']:
            if self.email_kargs[k] is None:
                can_doit = False
                break
        self.email_kargs['using_email'] = can_doit

    async def send_emails(self, results):
        using_email = self.email_kargs['using_email'] and \
                      isinstance(self.email_kargs['cc_list'], list) and \
                      len(self.email_kargs['cc_list']) < 1

        if using_email:
            return

        subject = self.email_kargs['subject']
        to = self.email_kargs['cc_list'][0]
        cc = self.email_kargs['cc_list'][1:] if len(self.email_kargs['cc_list']) > 1 else None
        _from = DOCKER_HP_EMAIL

        events = []
        for result in results:
            kargs = result.copy()
            r = result['request_data'].get('Cmd', [])
            kargs['command'] = " ".join(r)
            kargs['image'] = result['request_data'].get('Image', [])
            msg = ("{src_ip}:{src_port} creating image:{image} '''{command}'''".format(**kargs))
            events.append(msg)

        if len(events):
            # configure simple email
            # send email to server
            pass
