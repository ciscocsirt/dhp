from docker_honey.notify import Notifier
from docker_honey.server import DockerHp
from docker_honey.consts import *
from time import sleep
import asyncio
import argparse
from multiprocessing import Process

# require installation
parser = argparse.ArgumentParser()
parser.add_argument("-ports", help="ports to listen on", type=int,  nargs='+', default=PORTS)
parser.add_argument("-terminate_with_error", help="send a server error after create API call", action="store_true", default=False)
parser.add_argument("-error_message", help="error message to send after create API call", default=ERROR_MESSAGE, type=str)
parser.add_argument("-sensor_id", help="sensor identifier", default=DEFAULT_SENSOR_NAME, type=str)
parser.add_argument("-sensor_ip", help="sensor ip address", default=SENSOR_EXT_IP, type=str)

parser.add_argument("-http", help="send results to http endpoint", default=False, action='store_true')
parser.add_argument("-http_url", help="http endpoint url", default=None, type=str)
parser.add_argument("-http_verify_ssl", help="verify ssl (if no certificates specified)", default=HTTP_VERIFY_SSL, action='store_true')
parser.add_argument("-http_client_key", help="client key for authentication", default=None, type=str)
parser.add_argument("-http_client_crt", help="client certificate for authentication", default=None, type=str)
parser.add_argument("-http_server_crt", help="server certificate for authentication", default=None, type=str)
parser.add_argument("-http_token", help="http token", default=None, type=str)


parser.add_argument("-use_mongo", help="use mongo", default=False, action='store_true')
parser.add_argument("-mongo_db", help="mongo database to connect to", default=DATABASE, type=str)
parser.add_argument("-mongo_host", help="mongo host to connect to", default='127.0.0.1', type=str)
parser.add_argument("-mongo_port", help="mongo port go connect to", default=27017, type=int)
parser.add_argument("-mongo_user", help="mongo username", default=None, type=str)
parser.add_argument("-mongo_pass", help="mongo password", default=None, type=str)

parser.add_argument("-email", help="notify about attempt", action='store_true', default=False)
parser.add_argument("-email_notify_subject", help="email subject line", default=DEFAULT_SUBJECT, type=str)
parser.add_argument("-email_server", help="email server", default="smtp.gmail.com", type=str)
parser.add_argument("-email_port", help="email port", default=587, type=int)
parser.add_argument("-email_username", help="email server", default=None, type=str)
parser.add_argument("-email_password", help="email password", default=None, type=str)
parser.add_argument("-email_cc_list", help="email cc list", nargs='+', default=None, type=str)


# parser.add_argument("-slack_token", help="someone to email when event happens", default=None, type=str)
parser.add_argument("-slack", help="notify about attempt", action='store_true', default=False)
parser.add_argument("-slack_channel", help="slack channel tp post too", default=None, type=str)
parser.add_argument("-slack_username", help="username for webhook", default='docker_honey', type=str)
parser.add_argument("-slack_webhook", help="webhook url", default=None, type=str)
parser.add_argument("-slack_emoticon", help="slack emoticon to use", default=":suspect:", type=str)

parser.add_argument("-wbx", help="notify about attempt", action='store_true', default=False)
parser.add_argument("-wbx_webhook", help="webhook url", default=None, type=str)
    

def main(sensor_id, sensor_ip, notifier, port, terminate_with_error, error_message):
    honeypot = DockerHp(sensor_id, sensor_ip, notifier, port=port, 
                        terminate_with_error=terminate_with_error, error_message=error_message)
    loop = asyncio.get_event_loop()
    loop.create_task(honeypot.serve_forever())
    loop.run_forever()


if __name__ == "__main__":
    args = parser.parse_args()
    dargs = vars(args)

    
    terminate_with_error = args.terminate_with_error
    error_message = args.error_message
    sensor_id = args.sensor_id
    sensor_ip = args.sensor_ip
    notifier = Notifier(**dargs)

    processes = []
    try:
        for port in dargs['ports']:
            
            p = Process(target=main, 
                        args=(sensor_id, sensor_ip, notifier, port, terminate_with_error, error_message))
            p.start()
            processes.append(p)

        while True:
            if any([p.is_alive() for p in processes]):
                sleep(5.0)
    except KeyboardInterrupt:
        for p in processes:
            p.terminate()

    [p.join() for p in processes]
