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

import regex
import regex
import netifaces

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

DEFAULT_SENSOR_NAME = 'docker_honyepot'

DEFAULT_SENSOR_NAME = 'docker_honeypot'
SENSOR_EXT_IP = None
try:
    SENSOR_EXT_IP = requests.get("https://api.ipify.org/?format=json").json()['ip']
except:
    gws = netifaces.gateways()
    dft = gws.get('default', {})
    g = sorted(dft.items(), key=lambda k: k[0])
    if len(g) > 0:
        SENSOR_EXT_IP = g[0][1][0]


GLOBAL_NOTIFIER = None
GLOBAL_APP = None

USING_EMAIL = False
DOCKER_HP_EMAIL = 'no-reply@docker-honeypot.localhost'
EMAIL_KARGS = {
    "username": None,
    "password": None,
    "server": None,
    "port": None,
    "cc_list": None,
    "subject": None,
}

USING_SLACK = False
SLACK_KARGS = {
    "channel": None,
    "username": 'docker_honyepot',
    "webhook": None,
    "icon_emoji": ":suspect:",
}

USING_WBX_TEAMS = False
WBX_TEAMS_WEBHOOK = None


SLACK_WEBHOOK_PAYLOAD = {
    "channel": None, 
    "username": 'docker_honyepot', 
    "text": None, 
    "icon_emoji": ":suspect:",
}

USING_HTTP = False
HTTP_VERIFY_SSL = False
HTTP_TOKEN = None
HTTP_CLIENT_CRT = None
HTTP_CLIENT_KEY = None
TOKEN = 'token'
EVENTS = 'events'
SENSOR_IP = 'sensor_ip'
SENSOR_ID = 'sensor_id'



USING_MONGO = False
#MAX_DATA = 2000000000
MAX_DATA = 200000 # smaller machines wont work with large buffer.
PORTS = [2375, 2376, 2377, 4243, 4244]
API = '1.16'

KEEP_WORKING = False
ERROR_MESSAGE = 'server error'
DEFAULT_SUBJECT = "[DOCKERPOT] Create Attempted {src_host} to {dst_host}"

DATABASE = 'docker_honeypot'
REQUESTS_COLLECTION = 'connections'
COMMANDS_COLLECTION = 'commands'
IMAGES_COLLECTION = 'images'

PING_RE = rb'^HEAD \/_ping HTTP\/1\.1.*'
GET_RE = rb'^GET .*'
GET_VERSION_RE = rb'^GET \/(?<api>v[0-9]+\.[0-9]+)\/version.*'
CREATE_RE = rb'^POST \/(?<api>v[0-9]+\.[0-9]+)\/containers\/create.*'
CREATE_IMAGE_RE = rb"^POST \/(?<api>v[0-9]+\.[0-9]+)\/create\?.*"
ATTACH_RE = rb'^POST \/(?<api>v[0-9]+\.[0-9]+)\/containers\/[0-9a-f]+\/attach.*'
WAIT_RE = rb"^POST \/(?<api>v[0-9]+\.[0-9]+)\/containers\/[0-9a-f]+\/wait\?condition=removed.*"
START_RE = rb'^POST \/(?<api>v[0-9]+\.[0-9]+)\/containers\/[0-9a-f]+\/start.*' 
INFO_RE = rb'^GET \/(?<api>v[0-9]+\.[0-9]+)\/info HTTP/1.1'


GET_RETURN = b'''HTTP/1.1 200 OK\r\nApi-Version: {api}\r\nCache-Control: no-cache, no-store, must-revalidate\r\nContent-Type: text/plain; charset=utf-8\r\nDocker-Experimental: false\r\nOstype: linux\r\nPragma: no-cache\r\nServer: Docker/16.03.8 (linux)\r\nDate: {date}\r\n\r\n'''
PING_RETURN = b'''HTTP/1.1 200 OK\r\nApi-Version: {api}\r\nCache-Control: no-cache, no-store, must-revalidate\r\nContent-Length: {size}\r\nContent-Type: text/plain; charset=utf-8\r\nDocker-Experimental: false\r\nOstype: linux\r\nPragma: no-cache\r\nServer: Docker/16.03.8 (linux)\r\nDate: {date}\r\n\r\n'''
CREATE_RETURN = b'''HTTP/1.1 201 Created\r\nApi-Version: {api}\r\nContent-Type: application/json\r\nDocker-Experimental: false\r\nOstype: linux\r\nServer: Docker/16.03.8 (linux)\r\nDate: {date}\r\nContent-Length: 88\r\n\r\n{{"Id":"{docker_id}","Warnings":[]}}\r\n\r\n'''
CREATE_IMAGE_RETURN = b'''HTTP/1.1 200 Created\r\nApi-Version: {api}\r\nContent-Type: application/json\r\nDocker-Experimental: false\r\nOstype: linux\r\nServer: Docker/16.03.8 (linux)\r\nDate: {date}\r\nTransfer-Encoding: chunked\r\n0\r\n'''
WAIT_RETURN = b'''HTTP/1.1 200 OK\r\nApi-Version: {api}\r\nContent-Type: application/json\r\nDocker-Experimental: false\r\nOstype: linux\r\nServer: Docker/16.03.8 (linux)\r\nDate: {date}\r\nContent-Length: {size}\r\n\r\n{data}\r\n\r\n'''
ATTACH_RETURN = b'''HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n'''
ERROR_RETURN = b'''HTTP/1.1 500 Internal Server Error\r\nApi-Version: {api}\r\nContent-Type: application/json\r\nDocker-Experimental: false\r\nOstype: linux\r\nServer: Docker/16.03.8 (linux)\r\nDate: {date}\r\nContent-Length: {size}\r\n\r\n'''
ERROR_DATA = {"message":"server error"}

GET_VERSION_RETURN = b'''HTTP/1.1 200 OK\r\nApi-Version: {api}\r\nCache-Control: no-cache, no-store, must-revalidate\r\nContent-Length: {size}\r\nContent-Type: application/json; charset=utf-8\r\nDocker-Experimental: false\r\nOstype: linux\r\nPragma: no-cache\r\nServer: Docker/16.03.8 (linux)\r\nDate: {date}\r\n\r\n'''
GET_VERSION_DATA = {"Platform":{"Name":""},"Components":[{"Name":"Engine","Version":"16.03.8","Details":{"ApiVersion":"1.16","Arch":"amd64","BuildTime":"2015-01-18T21:26:54.000000000+00:00","Experimental":"false","GitCommit":"","GoVersion":"go1.0.8","KernelVersion":"2.4.0-42-generic","MinAPIVersion":"1.12","Os":"linux"}},{"Name":"containerd","Version":"1.0.0-0ubuntu2","Details":{"GitCommit":""}},{"Name":"runc","Version":"spec: 0.0.1-dev","Details":{"GitCommit":""}},{"Name":"docker-init","Version":"0.14.0","Details":{"GitCommit":""}}],"Version":"16.03.8","ApiVersion":"1.12","MinAPIVersion":"1.12","GitCommit":"","GoVersion":"go1.0.0","Os":"linux","Arch":"amd64","KernelVersion":"2.4.0-42-generic","BuildTime":"2015-01-18T21:26:54.000000000+00:00"}


INFO_RETURN = b'''HTTP/1.1 200 OK\r\nApi-Version: {api}\r\nContent-Type: application/json\r\nDocker-Experimental: false\r\nOstype: linux\r\nServer: Docker/16.03.8 (linux)\r\nDate: {date}\r\nContent-Length: {size}\r\n\r\n'''
INFO_DATA = {"ID":"","Containers":0,"ContainersRunning":1,"ContainersPaused":0,"ContainersStopped":9,"Images":6,"Driver":"aufs","DriverStatus":[["Root Dir","/var/lib/docker/aufs"],["Backing Filesystem","extfs"],["Dirs","141"],["Dirperm1 Supported","true"]],"SystemStatus":None,"Plugins":{"Volume":["local"],"Network":["bridge","host","ipvlan","macvlan","null","overlay"],"Authorization":None,"Log":["awslogs","fluentd","gcplogs","gelf","journald","json-file","local","logentries","splunk","syslog"]},"MemoryLimit":True,"SwapLimit":False,"KernelMemory":True,"KernelMemoryTCP":True,"CpuCfsPeriod":True,"CpuCfsQuota":True,"CPUShares":True,"CPUSet":True,"PidsLimit":True,"IPv4Forwarding":True,"BridgeNfIptables":True,"BridgeNfIp6tables":True,"Debug":False,"NFd":30,"OomKillDisable":True,"NGoroutines":41,"SystemTime":"{iso_date}","LoggingDriver":"json-file","CgroupDriver":"cgroupfs","NEventsListener":0,"KernelVersion":"5.4.0-42-generic","OperatingSystem":"Ubuntu 20.04 LTS","OSType":"linux","Architecture":"x86_64","IndexServerAddress":"https://index.docker.io/v1/","RegistryConfig":{"AllowNondistributableArtifactsCIDRs":[],"AllowNondistributableArtifactsHostnames":[],"InsecureRegistryCIDRs":["127.0.0.0/8"],"IndexConfigs":{"docker.io":{"Name":"docker.io","Mirrors":[],"Secure":True,"Official":True}},"Mirrors":[]},"NCPU":8,"MemTotal":33523802112,"GenericResources":None,"DockerRootDir":"/var/lib/docker","HttpProxy":"","HttpsProxy":"","NoProxy":"","Name":"mr-reimagined","Labels":[],"ExperimentalBuild":False,"ServerVersion":"16.03.8","ClusterStore":"","ClusterAdvertise":"","Runtimes":{"runc":{"path":"runc"}},"DefaultRuntime":"runc","Swarm":{"NodeID":"","NodeAddr":"","LocalNodeState":"inactive","ControlAvailable":False,"Error":"","RemoteManagers":None},"LiveRestoreEnabled":False,"Isolation":"","InitBinary":"docker-init","ContainerdCommit":{"ID":"","Expected":""},"RuncCommit":{"ID":"","Expected":""},"InitCommit":{"ID":"","Expected":""},"SecurityOptions":[],"Warnings":[]}

UNKNOWN_RETURN = b''

HAS_API = ['PING', 'GET_VERSION', 'CREATE', 'CREATE_IMAGE', 'WAIT', 'ATTACH', 'INFO', 'START']

WAIT_RETURN_DATA = b'{"Error":{random_string},"StatusCode":{random_string}}'


PING = 'PING'
GET = 'GET'
CREATE = 'CREATE'
CREATE_IMAGE = 'CREATE_IMAGE'
WAIT = 'WAIT'
ATTACH = 'ATTACH'
INFO = 'INFO'
START = 'START'
GET_VERSION = 'GET_VERSION'
ERROR = 'ERROR'
UNKNOWN = 'UNKNOWN'

IDENTIFY = {
    PING: regex.compile(PING_RE),
    GET_VERSION: regex.compile(GET_VERSION_RE),
    GET: regex.compile(GET_RE),
    CREATE: regex.compile(CREATE_RE),
    CREATE_IMAGE: regex.compile(CREATE_IMAGE_RE),
    WAIT: regex.compile(WAIT_RE),
    ATTACH: regex.compile(ATTACH_RE),
    INFO: regex.compile(INFO_RE),
    START: regex.compile(START_RE),

}

RESPONSES = {
    PING: PING_RETURN,
    GET: GET_RETURN,
    GET_VERSION: GET_VERSION_RETURN,
    CREATE: ERROR_RETURN,
    CREATE_IMAGE: ERROR_RETURN,
    WAIT: ERROR_RETURN,
    ATTACH: ERROR_RETURN,
    INFO: ERROR_RETURN,
    START: ERROR_RETURN,
    UNKNOWN: UNKNOWN_RETURN,
}

DEFAULT_HTTP_PORT = 9443
DATETIME = 'datetime'
REGISTERED = 'registered'
REGISTER_PATH = '/register'
PING_PATH = '/ping'


EMAIL = "email"
NAME = "name"
DESCRIPTION = "description"
IS_ADMIN = "is_admin"
FIRSTIES_TOKEN = 'there_can_be_only_one'

HONEYPOT_TOKEN = "honeypot_user"
HONEYPOT_DESCRIPTION = "a generic honeypot token for collection"
ALLOWED_TOKEN = 'collector_token'

USER_AGENT = 'user_agent'
HEADERS = 'headers'
JSON_PAYLOAD = 'json_payload'
DATA_PAYLOAD = 'data_payload'
PARAMETER_PAYLOAD = 'parameter_payload'
METHOD = 'method'
USER_AGENT_HEADER = 'User-Agent'
DEFAULT_USER_AGENT = 'curl/7.19.4 (i386-redhat-linux-gnu) libcurl/7.19.4 NSS/3.12.2.0 zlib/1.2.3 libidn/0.6.14 libssh2/0.18'
GET = 'get'
POST = 'post'
PUT = 'put'

DEFAULT_COLLECTOR_PORT = 5000
DEFAULT_COLLECTOR_PORT_ALT = 5001

COMMAND = 'command'
COMMAND_PERFORM_WEBREQ = "perform_web_request"
REQUEST_PARAMETERS = 'request_parameters'
RESPONSE_INFO = 'response_info'

EVENTS_ENDPOINT = '/events'
REGISTER_ENDPOINT = '/register'
DOWNLOAD_ENDPOINT = '/download_request/<result_id>' 
DOWNLOAD_LINK = "https://{host}:{port}/download_request/{result_id}"
SUMMARY_ENDPOINT = "/summary/<result_id>"
SUMMARY_LINK = "https://{host}:{port}/summary/{result_id}"

EVENT_ENDPOINT = "/event/<token>/<event_id>"
EVENT_LINK = "https://{host}:{port}/event/{token}/{event_id}"
EVENT_ID = 'event_id'

NEW_TOKEN_ENDPOINT = '/new_token'
PING_ENDPOINT = '/ping'
REQUESTS_ENDPOINT = '/requests'
COMMANDS_ENDPOINT = '/commands'
COMMANDS_RESPONSE_ENDPOINT = '/commands_response'
REMOTE_REQUEST_ENDPOINT = '/remote_web_request'

DEFAULT_HP_LADDR = '0.0.0.0'
DEFAULT_HP_LPORT = 61023
HP_COMMAND_ENDPOINT = '/commands'
GLOBAL_HOSTNAME = 'global_hostname'
GLOBAL_PORT = 'global_port'
CONFIG = 'config'
PARAMETERS = 'parameters'

DEFAULT_COLLECTOR_ADDR = '127.0.0.1'
DEFAULT_COLLECTOR_PORT = 5000
COLLECTOR_HTTP_DEFAULTS = {
    "collector": False,
    "collector_host": DEFAULT_COLLECTOR_ADDR,
    "collector_port": 5000,
    "collector_verify_ssl": False,
    "collector_crt": "./ssl/collector-cert.pem",
    "collector_key": "./ssl/collector-key.pem",
    "collector_ca": "./ssl/ca-dockerhp-collector.crt",
    "collector_ca_name": "ca-dockerhp-collector",
    "collector_common_name": "dockerhp-collector",
    "collector_url_fmt": "https://{collector_host}:{collector_port}",
    "collector_token": None,
    "collector_alt_host": None,
    "collector_alt_port": None,
}

DOCKERHP_HTTP_DEFAULTS = {
    "dockerhp_listen": False,
    "dockerhp_host": DEFAULT_HP_LADDR,
    "dockerhp_port": DEFAULT_HP_LPORT,
    "dockerhp_verify_ssl": False,
    "dockerhp_crt": "./ssl/dockerhp-cert.pem",
    "dockerhp_key": "./ssl/dockerhp-key.pem",
    "dockerhp_ca": "./ssl/ca-dockerhp-collector.crt",
    "dockerhp_ca_name": "ca-dockerhp-collector",
    "dockerhp_common_name": "dockerhp",
    "dockerhp_url_fmt": "https://{dockerhp_host}:{dockerhp_port}",
}

GLOBAL_CONFIGS = {
    "server_secret_key": None,
    "global_hostname": None,
    "global_port": None,
    "certs_path": None,
    "error_message": ERROR_MESSAGE,
}

MONGO_DEFAULTS = {
    "mongo": False,
    "mongo_db": "docker_honeypot",
    "mongo_ssl": True,
    "mongo_host": "fill_in_mongo_name_or_ip",
    "mongo_port": 27017,
    "mongo_user": "mongo_user",
    "mongo_pass": "fill_in_mongo_password_for_access",    
}
    
SLACK_DEFAULTS = {
    "slack": False,
    "slack_channel": "#tw-threat-intel",
    "slack_username": "docker-hp",
    "slack_webhook": None,
    "slack_emoticon": ":suspect:"
}

WBX_DEFAULTS = {
    "wbx": False,
    "wbx_webhook": None,
}

FAKE_COMMON_NAME = 'g00gle-com.info'

HYPERCORN_CONFIGURATION = "hypercorn --bind '{host}:{port}' --keyfile {certs_path}/{keyfile} --certfile {certs_path}/{certfile} --ca-certs {certs_path}/{ca_certfile} {exec_path}:{app}"



DOCKERHP_SG_NAME = 'docker-honeypot'
DOCKERHP_SECURITY_GROUPS = [DOCKERHP_SG_NAME] 
DOCKERHP_SG_DESCRIPTION = 'docker-honeypot security group'
DOCKERHP_IN_IP_PERMISSIONS =  [
    {'FromPort': 4240,
     'IpProtocol': 'tcp',
     'IpRanges': [{'CidrIp': '0.0.0.0/0',
       'Description': 'Inbound Docker Honeypot Connections'}],
     'Ipv6Ranges': [],
     'PrefixListIds': [],
     'ToPort': 4245,
     'UserIdGroupPairs': []},
    {'FromPort': 22,
     'IpProtocol': 'tcp',
     'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
     'Ipv6Ranges': [],
     'PrefixListIds': [],
     'ToPort': 22,
     'UserIdGroupPairs': []},
    {'FromPort': 2375,
     'IpProtocol': 'tcp',
     'IpRanges': [{'CidrIp': '0.0.0.0/0',
       'Description': 'Inbound Docker Honeypot Connections'}],
     'Ipv6Ranges': [],
     'PrefixListIds': [],
     'ToPort': 2380,
     'UserIdGroupPairs': []}
]


DOCKERHP_SG_OUT_IP_PERMISSIONS =  [{'IpProtocol': '-1',
     'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
     'Ipv6Ranges': [],
     'PrefixListIds': [],
     'UserIdGroupPairs': []}
]

REGION_TO_AMI = {
    'us-east-1':"ami-0bcc094591f354be2",
    'us-east-2':"ami-0bbe28eb2173f6167",
    'us-west-1':"ami-0dd005d3eb03f66e8",
    'us-west-2':"ami-0a634ae95e11c6f91",
    'sa-east-1':"ami-08caf314e5abfbef4",
    # 'ap-east-1':"ami-107d3e61",
    'ap-south-1':"ami-02b5fbc2cb28b77b8",
    'ap-southeast-1':"ami-0007cf37783ff7e10",
    'ap-southeast-2':"ami-0f87b0a4eff45d9ce",
    'ap-northeast-1':"ami-01c36f3329957b16a",
    'ap-northeast-2':"ami-05438a9ce08100b25",

    "eu-north-1": "ami-0363142d8c97b94c8",
    "eu-central-1": "ami-04932daa2567651e7",
    "eu-west-1": "ami-07ee42ba0209b6d77",
    "eu-west-2": "ami-04edc9c2bfcf9a772",
    "eu-west-3": "ami-03d4fca0a9ced3d1f",

}

DEFAULT_REGION = 'us-east-2'
DEFAULT_IMAGE_ID = REGION_TO_AMI[DEFAULT_REGION]
DCS = list(REGION_TO_AMI.keys())


DOCKERHP_INSTALL_SYSTEMCTL_COMMANDS = [
    'sudo cp hp_config.json /etc/hp_config.json'
    'sudo cp docker_honeypot.service /lib/systemd/system/',
    'sudo chmod 644 /lib/systemd/system/docker_honeypot.service',
    'sudo systemctl daemon-reload',
    'sudo systemctl enable docker_honeypot.service',
    'sudo systemctl start docker_honeypot.service',
    'sudo systemctl status docker_honeypot.service'

]

DOCKER_SETUP_COMMANDS = [
    'sudo apt update && sudo apt install -y apt-transport-https ca-certificates curl software-properties-common git python3-pip',
    'curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -',
    'sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"',
    'sudo apt update && sudo apt install -y docker-ce docker-compose',
    'sudo usermod -aG docker ${USER}',
]

DOCKERHP_SYSTEMCTL_CONFIG = '''[Unit]
Description=docker-honey pot service
After=syslog.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/dhp
ExecStart=/usr/bin/python3 /home/ubuntu/dhp/scripts/docker_honeypot.py -c /etc/hp_config.json

[Install]
WantedBy=multi-user.target
'''
REMOTE_WEB_REQUEST_CMD = 'remote_web_request'
URL = 'url'
STATUS_CODE = 'status_code'
HISTORY = 'history'
CONTENT = 'content'
CONTENT_ENCODING = 'content_encoding'
CONTENT_TYPE = 'content_type'
BASE64 = 'base64'
CONTENT_TYPE_ZIP = "application/zip"

WBX_DOWNLOAD_MESSAGE = '''**Downloaded URL:** `{url}` **{sensor_id} ({sensor_ip})**\n
**Content Results:** {download_link}\n
**Summary Link**: {summary_link}\n'''

SLACK_DOWNLOAD_MESSAGE = '''*Downloaded URL:* `{url}` *{sensor_id} ({sensor_ip})**\n
*Content Results:** {download_link}\n
*Summary Link*: {summary_link}\n'''
