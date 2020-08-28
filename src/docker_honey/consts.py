import regex
import requests
import regex
import netifaces
import logging

DEFAULT_SENSOR_NAME = 'docker_honyepot'
DOCKER_HP_LOGGER = None
COLLECTOR_LOGGER = None
logging.basicConfig(level=logging.INFO, format='%(asctime)s :: %(levelname)s :: %(message)s')
if DOCKER_HP_LOGGER is None:
    DOCKER_HP_LOGGER = logging.getLogger('docker_honeypot')
    COLLECTOR_LOGGER = logging.getLogger('collector')

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
