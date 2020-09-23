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


import os
import tempfile
import socket
import string
import json
import hashlib
import random
from datetime import datetime
import uuid
import requests
import netifaces
from validator_collection import validators, checkers
from .consts import *

get_server_date = lambda : datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')
get_docker_id = lambda : hashlib.sha256(get_server_date().encode('ascii')).hexdigest()
get_random_data = lambda : random_string_generator()
get_iso_time = lambda: datetime.now().isoformat()

def create_token(iters=1):
    return "-".join([str(uuid.uuid4()) for i in range(0, iters)])

def random_string_generator(str_size=25, allowed_chars=string.ascii_letters + string.punctuation):
    return ''.join(random.choice(allowed_chars) for x in range(str_size))

def random_alphanum_string_generator(str_size=25, allowed_chars=string.ascii_letters + string.punctuation):
    return random_string_generator(str_size=str_size, allowed_chars=string.ascii_letters)


def get_external_ip():
    ext_ip = ''

    gws = netifaces.gateways()
    dft = gws.get('default', {})
    g = sorted(dft.items(), key=lambda k: k[0])
    if len(g) > 0:
        ext_ip = g[0][1][0]
    
    try:
        ext_ip = requests.get("https://api.ipify.org/?format=json").json()['ip']
    except:
        pass
    return ext_ip

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


def create_certs(ca_name='server_ca', common_name:str=None, common_names:list=None, 
                 output_path="./ssl/"):

    common_names = common_names if common_names else []

    if common_name and common_name not in common_names:
        common_names.append(common_name)

    with tempfile.TemporaryDirectory() as tmpdirname:
        kargs = {
            "tmpdirname": os.path.join(tmpdirname, 'certstrap'),
            "bin_dir": os.path.join(tmpdirname, 'certstrap/bin'),
            "out_dir": output_path,
            "ca_name": ca_name,
            "ca_key_path": os.path.join(output_path, "{}.key".format(ca_name)),
            "ca_crl_path": os.path.join(output_path, "{}.crl".format(ca_name)),
            "ca_crt_path": os.path.join(output_path, "{}.crt".format(ca_name)),
            "certstrap_url": "https://github.com/square/certstrap/releases/download/v1.2.0/certstrap-1.2.0-linux-amd64",
            "certstrap_bin": "{}/certstrap".format(os.path.join(tmpdirname, 'certstrap/bin')),
            "output_path": output_path,
        }
        os.system("mkdir -p {output_path}".format(**kargs))
        os.system("mkdir -p {bin_dir}".format(**kargs))
        os.system("curl -fLs -o {certstrap_bin} {certstrap_url}".format(**kargs))
        os.system("chmod +x {certstrap_bin}".format(**kargs))
        os.system('{certstrap_bin} init --passphrase "" --common-name {ca_name} --expires "100 years"'.format(**kargs))

        os.system('cp ./out/{ca_name}.crt {ca_crt_path}'.format(**kargs))
        os.system('cp ./out/{ca_name}.crl {ca_crl_path}'.format(**kargs))
        os.system('cp ./out/{ca_name}.key {ca_key_path}'.format(**kargs))
        for common_name in common_names:
            kargs.update({
                "common_name": common_name,
                "cert_path": os.path.join(output_path, "{}-cert.pem".format(common_name)), 
                "key_path": os.path.join(output_path, "{}-key.pem".format(common_name)),
                "combined_path": os.path.join(output_path, "{}.pem".format(common_name)), 
            })

            os.system('{certstrap_bin} request-cert --passphrase "" --common-name {common_name}'.format(**kargs))
            os.system('{certstrap_bin} sign {common_name} --passphrase "" --CA {ca_name} --expires "100 years"'.format(**kargs))
            os.system('cp ./out/{common_name}.crt {cert_path}'.format(**kargs))
            os.system('cp ./out/{common_name}.key {key_path}'.format(**kargs))
            os.system('cat {key_path} {cert_path} > {combined_path}'.format(**kargs))
    
    os.system('rm -rf ./out/'.format(**kargs))

def dict_or_none(data):
    try:
        i = json.loads(data)
        if isinstance(i, dict):
            return i
        elif isinstance(i, list) and all([len(j) == 2 and isinstance(j, list) for j in i]):
            return {str(j[0]): j[1] for j in i}
        elif isinstance(i, int) or isinstance(i, str):
            return {str(i): ''}
    except:
        return None

def str_or_none(data):
    try:
        i = json.loads(data)
        j = str(i)
        if len(j) > 0:
            return data
        return None
    except:
        if len(data) > 0:
            return data
        return None

def url_or_none(data):
    try:
        return validators.url(data, allow_special_ips = True)
    except:
        return None

