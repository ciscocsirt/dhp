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

import argparse
import args
import os
import io
import scp
import paramiko
import boto3
import logging
import threading


AWS_ACCESS = None
AWS_SECRET = None

TAG_SPECIFICATIONS = [
    {'ResourceType': 'instance',
    'Tags': []
}]

UBUNTU = 'ubuntu'
INSTANCE_TYPE = 't2.micro'
WAIT_TIME = 30.0
DryRun = False

APPLICATION_NAME = 'docker-honeypot'
APPLICATION_NAME_KEY = 'ApplicationName'

TAGS = [('DataClassification', 'None'), 
        ('MailAlias', 'noone@nowhere.org'), 
        ('Name', 'None') 
        ('ApplicationName', APPLICATION_NAME), 
        ('ResourceOwner', 'None'),
        ('Environment', 'None')
        ]
DEFAULT_TAG_VALUES = {t: v for t, v in TAGS}


KEY_PATH = os.path.join(os.path.expanduser("~"), '.ssh/')
BASE_KEY_NAME = 'docker-honeypot-key'

REGION_TO_AMI = {
    'us-east-1':"ami-0bcc094591f354be2",
    'us-east-2':"ami-0bbe28eb2173f6167",
    'us-west-1':"ami-0dd005d3eb03f66e8",
    'us-west-2':"ami-0a634ae95e11c6f91",
    # 'sa-east-1':None,
    'ap-east-1':"ami-107d3e61",
    'ap-south-1':"ami-02b5fbc2cb28b77b8",
    'ap-southeast-1':"ami-0007cf37783ff7e10",
    'ap-southeast-2':"ami-0f87b0a4eff45d9ce",
    'ap-northeast-1':"ami-01c36f3329957b16a",
    'ap-northeast-2':"ami-05438a9ce08100b25",
}

DEFAULT_REGION = 'us-east-2'
DEFAULT_IMAGE_ID = REGION_TO_AMI[DEFAULT_REGION]
DCS = list(REGION_TO_AMI.keys())


INIT_COMMANDS = ['sudo apt update && sudo apt install -y python3-pip git',
                 'sudo apt update && sudo apt install -y python3-pip git',
                 'git clone https://github.com/ciscocsirt/dhp && cd dhp && pip3 install .'
                ]

SG_NAME = 'docker-honeypot'
SECURITY_GROUPS = [SG_NAME] 
SG_DESCRIPTION = 'docker-honeypot security group'
SG_IN_IP_PERMISSIONS =  [
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

SG_OUT_IP_PERMISSIONS =  [{'IpProtocol': '-1',
     'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
     'Ipv6Ranges': [],
     'PrefixListIds': [],
     'UserIdGroupPairs': []}
]

SERVICE_CONFIG = '''[Unit]
Description=docker-honey pot service
After=syslog.target

[Service]
Type=forking
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/dhp
PIDFile=/var/run/dhp.pid
ExecStart=/usr/bin/python3 /home/ubuntu/dhp/scripts/docker_honeypot.py {}

[Install]
WantedBy=multi-user.target
'''

TAG_MARKER = '--tag-'
PORTS = [2375, 2376, 2377, 4243, 4244]
COMMAND_ARGS_KEYWORDS = [
    "ports", "terminate_with_error",
    "http_verify_ssl", "http_url", "http_token",
    "slack_channel", "slack_username", "slack_webhook",
    "wbx_webhook",
]


parser = argparse.ArgumentParser()

parser.add_argument("-setup", help="setup instances", default=False, action="store_true")
parser.add_argument("-find", help="find all relevant instances based on application name", default=False, action="store_true")
parser.add_argument("-terminate", help="terminate all relevant instances based on application name", default=False, action="store_true")

parser.add_argument("-loglvl", help="logging level", default=logging.INFO)
parser.add_argument("-application_name", help="application name", default=APPLICATION_NAME)
parser.add_argument("-application_name_key", help="application name", default=APPLICATION_NAME_KEY)
parser.add_argument("-regions", help="regions to create honeypots in", default=[DEFAULT_REGION])
parser.add_argument("-ami", help="specific AMI to use in a single region", default=None)
parser.add_argument("-sg", help="Base security group name to use and create if not present", default=SG_NAME)
parser.add_argument("-key_name", help="Base keypair name to use and create if not present", default=BASE_KEY_NAME)
parser.add_argument("-key_path", help="Base keypair path, where keys are read from", default=KEY_PATH)
parser.add_argument("-max_count", help="Base keypair path, where keys are read from", default=KEY_PATH)


parser.add_argument("-aws_access_key_id", help="AWS access key", default=AWS_ACCESS)
parser.add_argument("-aws_secret_access_key", help="AWS secret key", default=AWS_SECRET)


parser.add_argument("-http", help="send results to http endpoint", default=False, action='store_true')
parser.add_argument("-http_url", help="http endpoint url", default=None, type=str)
parser.add_argument("-http_verify_ssl", help="verify ssl (if no certificates specified)", default=HTTP_VERIFY_SSL, action='store_true')
parser.add_argument("-http_client_key", help="client key for authentication", default=None, type=str)
parser.add_argument("-http_client_crt", help="client certificate for authentication", default=None, type=str)
parser.add_argument("-http_server_crt", help="server certificate for authentication", default=None, type=str)
parser.add_argument("-http_token", help="http token", default=None, type=str)

parser.add_argument("-slack", help="notify about attempt", action='store_true', default=False)
parser.add_argument("-slack_channel", help="slack channel tp post too", default=None, type=str)
parser.add_argument("-slack_username", help="username for webhook", default='docker_honey', type=str)
parser.add_argument("-slack_webhook", help="webhook url", default=None, type=str)
parser.add_argument("-slack_emoticon", help="slack emoticon to use", default=":suspect:", type=str)

parser.add_argument("-wbx", help="notify about attempt", action='store_true', default=False)
parser.add_argument("-wbx_webhook", help="webhook url", default=None, type=str)


def configure_tags(*extra_args, **kargs):
    tags = DEFAULT_TAG_VALUES.copy()

    for k,v in zip(extra_args[::2],extra_args[1::2]):        
        key = None
        if k.startswith(TAG_MARKER):
            key = [len(TAG_MARKER):]
        else:
            continue
        key = key.replace('-','_')

    for k, v in kargs.items():
        tags[k] = v

    tags_specs = [{'Key':k, 'Value': v} for k, v in tags.items()]
    tag_specification = TAG_SPECIFICATIONS.copy()
    tag_specification[0]['Tags'] = tags_specs
    return tag_specification


def generate_system_ctl_config(ports=PORTS, terminate_with_error=True, 
                               slack_channel=None, slack_username=None, slack_webhook=None,
                               wbx_webhook=None,
                               http_verify_ssl=False, http_url=None, http_token=None):

    config_args = {
        'ports': PORTS,
        # this gets populated later
        'sensor_id': '"{sensor_id}"'
    }

    if wbx_webhook is not None:
        config_args['wbx'] = ''
        config_args['wbx_webhook'] = '"{}"'.format(wbx_webhook)
    
    if slack_webhook is not None and \
       slack_username is not None and \
       slack_channel is not None:
        config_args['slack'] = ''
        config_args['slack_webhook'] = '"{}"'.format(slack_webhook)
        config_args['slack_channel'] = '"{}"'.format(slack_channel)
        config_args['slack_username'] = '"{}"'.format(slack_username)

    if http_url is not None and\
       http_token is not None:
        config_args['http'] = ''
        config_args['http_token'] = '"{}"'.format(http_token)
        config_args['http_url'] = '"{}"'.format(http_url)

    the_args = ' '.join([" -"+k+' '+v for k, v in config_args.items()])
    return SERVICE_CONFIG.format(the_args)


def get_key_pair(ec2, key_name=BASE_KEY_NAME, key_path=KEY_PATH, recreate=False):
    key_filename = os.path.join(key_path, key_name)
    try:
        ec2.describe_key_pairs(KeyNames=[key_name])
        if os.path.exists(key_path) and not recreate:
            return key_filename
    except:
        pass

    print("Unable to find keys, creating new key: {}, writing to: {}".format(key_name, key_path)) 

    outfile = open(key_filename,'w')
    key_pair = ec2.create_key_pair(KeyName=key_name)
    KeyPairOut = str(key_pair['KeyMaterial'])
    outfile.write(KeyPairOut)
    return key_filename

def create_security_group(ec2, sg_name=SG_NAME, sg_description=SG_DESCRIPTION, ingress=SG_IN_IP_PERMISSIONS):
    try:
        rsp = ec2.describe_security_groups(GroupNames=[sg_name])
        return rsp['SecurityGroups'][0]['GroupId']
    except:
        pass

    rsp = ec2.create_security_group(GroupName=sg_name,
                                         Description=sg_description)
    sg_id = rsp.get('GroupId', None)

    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ingress)
    return sg_id


def create_instances(ec2, KeyName, MaxCount=1,
                     ImageId=DEFAULT_IMAGE_ID, InstanceType=INSTANCE_TYPE,
                     SecurityGroups=SECURITY_GROUPS, TagSpecifications=TAG_SPECIFICATIONS):
    
    print("Creating {} instances".format(MaxCount))

    reservations = ec2.run_instances(
        DryRun=False, 
        MinCount=1, 
        MaxCount=MaxCount, 
        ImageId=ImageId, 
        KeyName=KeyName, 
        InstanceType=InstanceType, 
        SecurityGroups=SecurityGroups, 
        TagSpecifications=TagSpecifications
    ) 

    instances = [i['InstanceId'] for i in reservations['Instances']]
    print("Created {} instances".format(len(instances)))
    return instances

def check_for_instances_up(ec2, instances):
    instances_completed_loading = []
    statuses = ec2.describe_instance_status(InstanceIds=instances)
    for status in statuses['InstanceStatuses']:
        instance_id = status['InstanceId']
        if status['InstanceState']['Code'] != 16:
            continue
        if status['InstanceStatus']['Status'] != 'ok':
            continue
        if status['SystemStatus']['Status'] != 'ok':
            continue

        print ("Instance appears to have completed loading", instance, statuses)
        instances_completed_loading.append(instance_id)
    return instances_completed_loading


def get_public_ips(ec2, instances):
    results = ec2.describe_instances(InstanceIds=instances)
    instance_infos = []
    for k in results['Reservations']:
        instance_infos = instance_infos + k['Instances']
    
    instance_to_ip = {k['InstanceId']: k.get('PublicIpAddress', '') for k in instance_infos}
    print("Got {} instances IP addresses".format(len(instances)))
    return instance_to_ip    

def setup_instance(instance, ip, region, service_config, key_filename, username=UBUNTU):
    print("Setting up {} @ IP addresses: {}".format(instance, ip))
    sensor_id = "{}:|:{}:|:{}".format(region, ip, instance)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=UBUNTU, key_filename=KEYFILE)
    for cmd in INIT_COMMANDS:
        stdin, stdout, stderr = client.exec_command(cmd)
        print(stdout.read())

    print("executed set up commands for {} @ IP addresses: {}".format(instance, ip))
    stdout.read()
    scp_client = scp.SCPClient(client.get_transport())
    print("scp'ing the systemctl file for {} @ IP addresses: {}, sensor_id: {}".format(instance, ip, sensor_id))
    new_file = io.BytesIO(service_config.format(**{'sensor_id':sensor_id}).encode('ascii'))
    scp_client.putfo(new_file, './docker_honeypot.service')
    client.exec_command('sudo cp docker_honeypot.service /lib/systemd/system/')
    client.exec_command('sudo chmod 644 /lib/systemd/system/docker_honeypot.service')
    client.exec_command('sudo systemctl daemon-reload')
    client.exec_command('sudo systemctl enable docker_honeypot.service')
    client.exec_command('sudo systemctl start docker_honeypot.service')
    stdin, stdout, stderr = client.exec_command('sudo systemctl status docker_honeypot.service')
    print(stdout.read())


def doit_defaults(max_count=3, regions=DCS, aws_access_key_id=AWS_ACCESS, aws_secret_access_key=AWS_SECRET,
                  key_path=KEY_PATH, base_key_name=BASE_KEY_NAME, sg_name=SG_NAME, *extra_args, **kargs):
    instances = []

    dhp_command_kargs = {k:kargs.get(k, None) for k in COMMAND_ARGS_KEYWORDS}
    if dhp_command_kargs['ports'] is None:
        dhp_command_kargs['ports'] = PORTS

    service_config = generate_system_ctl_config(**dhp_command_kargs)
    tag_specification = configure_tags(*extra_args, **kargs)

    for k in dhp_command_kargs:
        if k in kargs:
            del kargs[k]

    for dc in regions:
        try:
            
            ec2 = boto3.client('ec2', 
                               dc, 
                               aws_access_key_id=aws_access_key_id, 
                               aws_secret_access_key=aws_secret_access_key) 

            ami = REGION_TO_AMI.get(dc, None)
            if ami is None:
                ami = DEFAULT_IMAGE_ID

            key_name = base_key_name + '-' + dc
            print("setting up keypair {} for instances".format(key_name))
            key_filename = get_key_pair(ec2, key_name)

            print("setting up security group {} for instances".format(sg_name))
            sg_id = create_security_group(ec2, sg_name)
            print("creating {} instances in {} region".format(MaxCount, dc))
            instances = create_instances(ec2, key_name, 
                                         ImageId=ami, 
                                         MaxCount=max_count,
                                         TagSpecifications=tag_specification)
            
            print("waitng for {} instances in {} region".format(MaxCount, dc))
            time.sleep(WAIT_TIME)
            print("getting IPs for {} instances in {} region".format(MaxCount, dc))
            instance_to_ip = get_public_ips(ec2, instances)
            
            completed_loading = check_for_instances_up(ec2, instances)
            while len(completed_loading) != len(instances):
                print("Waiting {} before recheck of {} instances".format(WAIT_TIME, len(instances)))
                time.sleep(WAIT_TIME)
                completed_loading = check_for_instances_up(ec2, instances)
            
            time.sleep(3.0)
            print("setting up {} instances in {} region".format(MaxCount, dc))
            threads = []
            for instance, ip in instance_to_ip.items():
                t = threading.Thread(target=setup_instance, args=(instance, ip, dc, service_config, key_filename))
                t.start()
                threads.append(t)

            for t in threads:
                t.join()

        except:
            print("Failed to create {} instances in {} region".format(MaxCount, dc))
            raise

    return instances

def find_relevant_instances(region, aws_access_key_id=AWS_ACCESS, 
                            aws_secret_access_key=AWS_SECRET, 
                            application_name=APPLICATION_NAME,
                            application_name_key=APPLICATION_NAME_KEY):
    relevant_instances = []
    ec2 = boto3.client('ec2', 
                       region, 
                       aws_access_key_id=aws_access_key_id, 
                       aws_secret_access_key=aws_secret_access_key)
    rsp = ec2.describe_instances()
    reservations = rsp.get('Reservations', {})
    for reservation in reservations:
        instances = reservation.get('Instances', [])
        for instance in instances:
            tags = instance.get('Tags')
            instance_id = instance['InstanceId']
            for tag in tags:
                if tag.get('Key', '') == application_name_key and \
                   tag.get('Value', '') == application_name:
                   relevant_instances.append(instance_id)
    return sorted(set(relevant_instances))

def find_relevant_instances_multiple_regions(regions=DCS, aws_access_key_id=AWS_ACCESS, 
                            aws_secret_access_key=AWS_SECRET, 
                            application_name=APPLICATION_NAME,
                            application_name_key=APPLICATION_NAME_KEY,
                            **kargs):
    relevant_instances = []
    for region in regions:
        instances = find_relevant_instances(region,
                            aws_access_key_id=aws_access_key_id, 
                            aws_secret_access_key=aws_secret_access_key, 
                            application_name=application_name,
                            application_name_key=application_name_key)
        relevant_instances = relevant_instances + instances
    return sorted(set(relevant_instances))
    
def terminate_relevant_instances(region, aws_access_key_id=AWS_ACCESS, 
                            aws_secret_access_key=AWS_SECRET,
                            application_name=APPLICATION_NAME,
                            application_name_key=APPLICATION_NAME_KEY,
                            instances: list =None, DryRun=True):
    if instances is None:
        instances = []

    ec2 = boto3.client('ec2', 
                   region, 
                   aws_access_key_id=aws_access_key_id, 
                   aws_secret_access_key=aws_secret_access_key)

    instances = instances + find_relevant_instances(region, aws_access_key_id=AWS_ACCESS, 
                            aws_secret_access_key=AWS_SECRET,
                            application_name=APPLICATION_NAME,
                            application_name_key=APPLICATION_NAME_KEY)
    if len(instances) == 0:
        return instances
    return ec2.terminate_instances(DryRun=DryRun, InstanceIds=instances)

def terminate_relevant_instances_multiple_regions(regions=DCS, aws_access_key_id=AWS_ACCESS, 
                            aws_secret_access_key=AWS_SECRET,
                            application_name=APPLICATION_NAME,
                            application_name_key=APPLICATION_NAME_KEY,
                            instances: list =None, DryRun=True,
                            **kargs):
    results = []
    for region in regions:
        r = terminate_relevant_instances(region, aws_access_key_id=aws_access_key_id, 
                            aws_secret_access_key=aws_secret_access_key,
                            application_name=application_name,
                            application_name_key=application_name_key, DryRun=DryRun)
        results.append(r)
    return results



if __name__ == "__main__":
    args, extra_args = 
    args, extras = parser.parse_known_args()
    dargs = vars(args)

    if dargs["setup"]:
        doit_defaults(*extras, **dargs)
    elif dargs["find"]:
        results = find_relevant_instances_multiple_regions(**dargs)
        print("Found the following instances", "\n".join(results))
    elif dargs["terminate"]:
        results = terminate_relevant_instances_multiple_regions(**dargs)        
        print("Termination results for the following instances:", results)
