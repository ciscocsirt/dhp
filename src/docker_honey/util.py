import socket
import string
import json
import hashlib
import random
from datetime import datetime

from .consts import *

get_server_date = lambda : datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')
get_docker_id = lambda : hashlib.sha256(get_server_date().encode('ascii')).hexdigest()
get_random_data = lambda : random_string_generator()
get_iso_time = lambda: datetime.now().isoformat()


def random_string_generator(str_size=25, allowed_chars=string.ascii_letters + string.punctuation):
    return ''.join(random.choice(allowed_chars) for x in range(str_size))


def extract_json_data(req):
    data = None
    if isinstance(req, bytes):
        data_l = req.split(b'\r\n\r\n')
        if len(data_l) > 0:
            data = b"\r\n\r\n".join(data_l[1:])
        else:
            return None

    if isinstance(req, str):
        data_l = req.split('\r\n\r\n')
        if len(data_l) > 0:
            data = "\r\n\r\n".join(data_l[1:])
        else:
            return None
    try:
        if data:
            return json.loads(data)
    except:
        raise

    return None

def get_match_group(rtype, req):
    if not rtype in IDENTIFY:
        return {}
    r = IDENTIFY[rtype].match(req)
    if r is None:
        return {}
    return r.groupdict()

def generate_error(error_message='server error', api=API):
    fmt = RESPONSES.get(ERROR, ERROR_RETURN)
    ed = ERROR_DATA.copy()
    ed['message'] = error_message
    data = json.dumps(ed)
    size = len(data)
    kargs = {'api': api}
    kargs.update({
        'docker_id': get_docker_id(),
        'date': get_server_date(),
        'size': size,
        'iso_date': get_iso_time(),
    })
    resp = fmt.decode('ascii').format(**kargs)+data
    return resp


def create_response(rtype, req):
    size = 0
    data = b''
    fmt = RESPONSES.get(rtype, GET_RETURN)
    kargs = get_match_group(rtype, req)
    kargs['api'] = API if not 'api' in kargs else kargs['api'].decode('ascii').lstrip('v') 

    if INFO_RETURN == fmt:
        data = json.dumps(INFO_DATA).replace('{iso_date}', get_iso_time())
        size = len(data)
    elif WAIT_RETURN == fmt:
        data = json.dumps(WAIT_RETURN_DATA).replace('{random_string}', get_random_data())
        size = len(data)
    elif ERROR_RETURN == fmt:
        data = json.dumps(ERROR_DATA)
        size = len(data)
    elif GET_VERSION_RETURN == fmt:
        data = json.dumps(GET_VERSION_DATA).replace('{api}', kargs['api'])
        size = len(data)

    kargs.update({
        'docker_id': get_docker_id(),
        'date': get_server_date(),
        'size': size,
        'iso_date': get_iso_time(),
    })
    if isinstance(data, bytes):
        data = data.decode('ascii')

    resp = fmt.decode('ascii').format(**kargs)+data
    return resp

def get_handler_type(data):
    rtype = UNKNOWN
    for name, re in IDENTIFY.items():
        if re.match(data):
            rtype = name
            break
    return rtype

def get_docker_sock():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect('/var/run/docker.sock')
    return sock

def create_listener_sock(port):
    s = socket.socket()
    s.bind(('', port))
    s.listen(10)
    return s


def recv_until_done(client):
    data = b''
    while True:
        new_data = b''
        try:
            new_data = client.recv(MAX_DATA)
        except:
            pass
        data = data + new_data
        if data.find(b'GET') == 0 and new_data.find(b'\r\n\r\n') > 3:
            return data
        elif data.find(b'GET') == 0 and new_data.find(b'\n\n') > 3:
            return data
        elif new_data == b'':
            break
    return data
