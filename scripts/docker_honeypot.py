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

from docker_honey.notify import Notifier
from docker_honey.simple_commands.app import Hypercorn as App
from docker_honey.server import DockerHp
from docker_honey.consts import *
from docker_honey.dockerhp_actions import *
from docker_honey.simple_commands.util import *

from time import sleep
import asyncio
import argparse
from multiprocessing import Process
from quart import Quart, jsonify, Response, request
import json

LOGGER = get_stream_logger(__name__)
# require installation
parser = argparse.ArgumentParser()
parser.add_argument("-config", help="path to the configuration", type=str,  default=None)


NOTIFIER = None

PROCESSES = []
def start_command_listener(host, port, certs_path, ca_crt, server_crt, server_key, secret_key):
    LOGGER.info("settingup command_listener")
    # print(get_single_notifier().server_secret_key)
    app = App('docker-hp-commands', host='0.0.0.0', port=port, certs_path=certs_path,
              ca_crt=ca_crt, server_crt=server_crt, server_key=server_key)

    app.add_url_rule(HP_COMMAND_ENDPOINT, 'commands', handle_remote_commands, methods = ['POST'])
    try:
        LOGGER.info("Starting command_listener app")
        app.quart_run()
    except KeyboardInterrupt:
        pass
    except:
        pass
    
    LOGGER.info("Exiting from start_command_listener")


def main(sensor_id, sensor_ip, notifier, ports, terminate_with_error, error_message):
    honeypot = DockerHp(sensor_id, sensor_ip, notifier, ports=ports, 
                        terminate_with_error=terminate_with_error, error_message=error_message)
    LOGGER.info("Starting main")
    try:
        loop = asyncio.get_event_loop()
        loop.create_task(honeypot.serve_forever())
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    except:
        pass

    LOGGER.info("Exiting from main")


async def wait_forever():
    p = [p.is_alive() for p in PROCESSES]
    await get_single_notifier().send_registration()
    sleep(60.0)
    while len(p) > 0:
        try:
            await get_single_notifier().send_ping()
            sleep(60.0)
            p = [p.is_alive() for p in PROCESSES]
        except KeyboardInterrupt:
            break
        except:
            pass
    LOGGER.info("Exiting from wait_forever")

if __name__ == "__main__":
    args = parser.parse_args()
    dargs = vars(args)
    if args.config:
        config_path = args.config
        del dargs[CONFIG]
        config = json.load(open(config_path))
        dargs.update(config)

    if dargs.get('global_hostname', None):
        dargs['global_hostname'] = get_external_ip()
        dargs['global_port'] = DEFAULT_HP_LPORT

    terminate_with_error = dargs.get('terminate_with_error', True)
    error_message = dargs.get('error_message', ERROR_MESSAGE)
    sensor_id = dargs.get('sensor_id', None)
    sensor_ip = dargs.get('sensor_ip', None)


    if sensor_ip is None:
        sensor_ip = get_external_ip()
        dargs["sensor_ip"] = sensor_ip

    if sensor_id is None:
        sensor_id = "{}-{}".format(DEFAULT_SENSOR_NAME, sensor_ip)
        dargs['sensor_id'] = sensor_id


    listen = dargs.get("dockerhp_listen", False)
    listen_address = '0.0.0.0'
    listen_port = dargs.get("dockerhp_port", DEFAULT_HP_LPORT)

    listen_port = listen_port if listen_port else DEFAULT_HP_LPORT 
    listen_address = listen_address if listen_address else DEFAULT_HP_LADDR

    server_ca = dargs.get("dockerhp_ca_crt", None)
    server_crt = dargs.get("dockerhp_crt", None)
    server_key = dargs.get("dockerhp_key", None)
    secret_key = dargs.get("server_secret_key", None)
    certs_path = dargs.get("certs_path", None)
    NOTIFIER = get_single_notifier(**dargs)
    # print(secret_key)

    PROCESSES = []
    try:
        if listen:
            p = Process(target=start_command_listener, 
                        args=(listen_address, listen_port, certs_path, server_ca, server_crt, server_key, secret_key))
            p.start()
            PROCESSES.append(p)
            
        p = Process(target=main, 
                    args=(sensor_id, sensor_ip, get_single_notifier(), dargs['ports'], terminate_with_error, error_message))
        p.start()
        PROCESSES.append(p)

    except KeyboardInterrupt:
        pass

    # print(PROCESSES)
    try:
        loop = asyncio.get_event_loop()
        asyncio.run(wait_forever())
    except KeyboardInterrupt:
        for p in PROCESSES:
            p.terminate()        
    except:
        pass

    for p in PROCESSES:    
        if p.is_alive():
            os.system('kill -9 {}'.format(p.pid))
