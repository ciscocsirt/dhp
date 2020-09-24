import sys
import subprocess
from docker_honey.util import *
from docker_honey.collector_actions import *
from docker_honey.commands import *
from docker_honey.consts import GLOBAL_NOTIFIER as NOTIFIER
from docker_honey.consts import *
from docker_honey.notify import *
from docker_honey.simple_commands.app import Hypercorn as App
from docker_honey.simple_commands.util import *

from docker_honey.simple_commands.consts import *
from docker_honey.simple_commands import boto
from docker_honey.simple_commands import ssh
from docker_honey.simple_commands.actions import *
import json
import os

from multiprocessing import Process
from threading import Thread
from time import sleep
import asyncio
import argparse
from multiprocessing import Process
from quart import Quart, jsonify, Response, request
import json
import sys
from hypercorn.config import Config
from hypercorn.asyncio import serve

LOGGER = get_stream_logger(__name__)

NEW_SECRETS = 'new_secrets_file.json'
parser = argparse.ArgumentParser()
parser.add_argument("-config", help="json config to load from", default=None)
parser.add_argument("-secrets", help="json config containing sensitive parameters", default=None)
parser.add_argument("-new_secrets_file", help="json config with updated secrets", default=NEW_SECRETS)
parser.add_argument("-recreate_keys", help="recreate ssh keys", default=False, action="store_true")

parser.add_argument("-mongodb_up", help="bring up the mongodb instance", default=False, action="store_true")
parser.add_argument("-mongodb_down", help="bring down the mongo instance", default=False, action="store_true")
parser.add_argument("-mongodb_delete_vols", help="delete the mongo volumes", default=False, action="store_true")
parser.add_argument("-mongodb_region", help="region for mongodb", default="us-east-2")

parser.add_argument("-collector_up", help="bring up the collector instance", default=False, action="store_true")
parser.add_argument("-collector_down", help="bring down the collector instance", default=False, action="store_true")
parser.add_argument("-collector_region", help="region for the collector", default="us-east-2")
parser.add_argument("-collector_count", help="number of collecters to deploy (max 2)", default=1)
parser.add_argument("-collector_config", help="base collector configuration to update and upload to the instance",
                    default="./samples/collector_config_sample.json")

parser.add_argument("-dockerhp_up", help="bring up the docker-hp instances", default=False, action="store_true")
parser.add_argument("-dockerhp_down", help="bring down the docker-hp instances", default=False, action="store_true")
parser.add_argument("-dockerhp_regions", help="regions for the honeypot", nargs='+', default=["us-east-2"])
parser.add_argument("-dockerhp_count", help="number of docker honeypots to deploy", default=1, type=int)
parser.add_argument("-dockerhp_config", help="base collector configuration to update and upload to the instance",
                    default="./samples/hp_config_sample.json")



DOCKERHP_TAGS = {
    'ApplicationName': "dockerhp-application", 
    'Name': 'dockerhp'
}

COLLECTOR_TAGS = {
    'ApplicationName': "dockerhp-application", 
    'Name': 'dockerhp-collector'
}

MONGODB_TAGS = {
    'ApplicationName': "dockerhp-application", 
    'Name': 'dockerhp-mongodb'
}

def instance_down(instance_type, regions=['us-east-2']):
    if instance_type == 'mongodb':
        boto.Commands.terminate_relevant_instances_multiple_regions(regions=regions, target_tags=MONGODB_TAGS, dry_run=False)
    elif instance_type == 'mongodb_vols':
        boto.Commands.delete_relevant_volumes_multiple_regions(regions=regions, target_tags=MONGODB_TAGS, dry_run=False)
    elif instance_type == 'collector':
        boto.Commands.terminate_relevant_instances_multiple_regions(regions=regions, target_tags=COLLECTOR_TAGS, dry_run=False)
    elif instance_type == 'dockerhp':
        boto.Commands.terminate_relevant_instances_multiple_regions(regions=regions, target_tags=DOCKERHP_TAGS, dry_run=False)


def handle_dockerhp_config_update_and_start(instance_name, region: str, base_config: str, dockerhp_instances: dict, 
                                             instance_public_ip: dict, command_format_args: dict, boto_config: dict):

    dockerhp_config = base_config.copy()
    collector_host = command_format_args.get('collector_host')
    collector_alt_host = command_format_args.get('collector_alt_host')
    collector_port = command_format_args.get('collector_port')
    collector_alt_port = command_format_args.get('collector_alt_port')
    collector_token = command_format_args.get('collector_token')
    server_secret_key = command_format_args.get('server_secret_key')
    # admin_token = command_format_args.get('admin_token', None)
    honeypot_tokens = command_format_args.get('honeypot_tokens')
    if len(honeypot_tokens) > 0:
        collector_token = honeypot_tokens[0]
    
    if collector_alt_host is None:
        collector_alt_host = collector_host

    if collector_port is None:
        collector_port = 5000

    if collector_alt_port is None:
        collector_alt_port = 5001

    dockerhp_config["server_secret_key"] = server_secret_key
    dockerhp_config['collector_host'] = collector_host
    dockerhp_config['collector_alt_host'] = collector_host
    dockerhp_config['collector_port'] = collector_port
    dockerhp_config['collector_alt_port'] = collector_alt_port
    dockerhp_config["collector_token"] = collector_token
    dockerhp_config["collector"] = True
    dockerhp_config['honeypot_tokens'] = None
    dockerhp_config['wbx'] = False
    dockerhp_config['wbx_webhook'] = None
    dockerhp_config['slack'] = False
    dockerhp_config['slack_webhook'] = None

    if 'aws_access_key_id' in dockerhp_config:
        del dockerhp_config['aws_access_key_id']

    if 'aws_secret_access_key' in dockerhp_config:
        del dockerhp_config['aws_secret_access_key']

    key_info = boto.Commands.get_instance_key_info(instance_name, boto_config, region=region)
    key_name = key_info.get("key_name", None)
    key_filename = boto.Commands.get_key_pair(key_info['key_name'], key_info['key_path'], 
                                              recreate=False, region=region, **boto_config)

    for instance, ip in instance_public_ip.items():            
        dockerhp_config["sensor_id"] = "{}:|:{}:|:{}".format(region, ip, instance)
        dockerhp_config['global_hostname'] = ip
        config_bytes = json.dumps(dockerhp_config, sort_keys=True, indent=6).encode('ascii')
        # print(json.dumps(dockerhp_config, indent=6, sort_keys=True))
        ssh.Commands.upload_bytes(config_bytes, "hp_config.json", host=ip, key_filename=key_filename, username=UBUNTU)
    
    activity_name = "startup" 
    return perform_activity(instance_name, dockerhp_instances, activity_name, instance_public_ip, boto_config, command_format_args)

def handle_collector_config_update_and_start(instance_name, region: str, base_config: str, collector_instances: dict, 
                                             instance_public_ip: dict, command_format_args: dict, boto_config: dict):
    
    if 'aws_access_key_id' in base_config:
        del base_config['aws_access_key_id']
    if 'aws_secret_access_key' in base_config:
        del base_config['aws_secret_access_key']

    collector_config = base_config.copy()
    alt_collector_config = base_config.copy()

    collector_host = command_format_args.get('collector_host')
    alt_collector_host = command_format_args.get('alt_collector_host')
    if alt_collector_host is None:
        alt_collector_host = collector_host
    collector_token = command_format_args.get('collector_token')
    server_secret_key = command_format_args.get('server_secret_key')
    honeypot_tokens = command_format_args.get('honeypot_tokens', None)
    admin_tokens = command_format_args.get('admin_token', None)
    slack_webhook = command_format_args.get('slack_webhook', None)
    wbx_webhook = command_format_args.get('wbx_webhook', None)
    admin_token = command_format_args.get('admin_token', None)
    mongo_host = command_format_args.get('mongo_host', None)
    mongo_pass = command_format_args.get('mongo_pass', None)
    

    slack = slack_webhook is None
    wbx = wbx_webhook is None

    # primary collector
    # collector_config["collector_token"] = collector_token
    collector_config['global_hostname'] = collector_host
    collector_config["server_secret_key"] = server_secret_key
    collector_config["admin_token"] = admin_token
    collector_config["honeypot_tokens"] = sorted(set(honeypot_tokens))
    collector_config["slack_webhook"] = slack_webhook
    collector_config["slack"] = not slack_webhook is None
    collector_config["wbx_webhook"] = wbx_webhook
    collector_config["wbx"] = not wbx_webhook is None
    collector_config['mongo'] = not mongo_host is None
    collector_config['mongo_host'] = mongo_host
    collector_config['mongo_pass'] = mongo_pass

    # alternate collector
    alt_collector_config['global_hostname'] = alt_collector_host
    alt_collector_config["server_secret_key"] = server_secret_key
    alt_collector_config["admin_token"] = admin_token
    alt_collector_config["honeypot_tokens"] = sorted(set(honeypot_tokens))
    alt_collector_config["slack_webhook"] = slack_webhook
    alt_collector_config["slack"] = not slack_webhook is None
    alt_collector_config["wbx_webhook"] = wbx_webhook
    alt_collector_config["wbx"] = not wbx_webhook is None
    alt_collector_config['mongo'] = not mongo_host is None
    alt_collector_config['mongo_host'] = mongo_host
    alt_collector_config['mongo_pass'] = mongo_pass


    key_info = boto.Commands.get_instance_key_info(instance_name, boto_config, region=region)
    key_name = key_info.get("key_name", None)
    key_filename = boto.Commands.get_key_pair(key_info['key_name'], key_info['key_path'], 
                                              recreate=False, **boto_config)

    username = UBUNTU
    config_bytes = json.dumps(collector_config, sort_keys=True, indent=6).encode('ascii')
    ssh.Commands.upload_bytes(config_bytes, "collector_config.json", host=collector_host, key_filename=key_filename, username=username)
    config_bytes = json.dumps(alt_collector_config, sort_keys=True, indent=6).encode('ascii')
    if alt_collector_host is not None and alt_collector_host != collector_host:
        ssh.Commands.upload_bytes(config_bytes, "collector_config.json", host=alt_collector_host, key_filename=key_filename, username=username)
    activity_name = "startup"
    return perform_activity(instance_name, collector_instances, activity_name, instance_public_ip, boto_config, command_format_args)

def deploy_dockerhp(args, boto_config, boto_secrets):

    base_config = json.load(open(args.dockerhp_config))
    base_config = merge_dicts(base_config, boto_secrets)
    # check mongo is valid
    if base_config.get("mongo", False):
        mongo_pass = base_config.get('mongo_pass', None)
        mongo_host = base_config.get('mongo_host', None)
        if mongo_pass is None:
            LOGGER.critical("Missing 'mongo_pass', exiting")
        elif mongo_host is None:
            LOGGER.critical("Missing 'mongo_host', exiting")
    
    if base_config.get("slack", False):
        if base_config.get("slack_webhook", None) is None:
            LOGGER.critical("Missing 'slack_webhook', exiting")

    if base_config.get("wbx", False):
        if base_config.get("wbx_webhook", None) is None:
            LOGGER.critical("Missing 'wbx_webhook', exiting")

    server_secret_key = base_config.get("server_secret_key", None)
    if server_secret_key is None:
        server_secret_key = random_alphanum_string_generator()
        update_config('server_secret_key', server_secret_key, boto_secrets)
        base_config = merge_dicts(base_config, boto_secrets)
        json.dump(boto_secrets, open(args.new_secrets_file, 'w'), indent=6, sort_keys=True)

    collector_token = boto_secrets.get('collector_token', None)
    if collector_token is None:
        collector_token = random_alphanum_string_generator()
        update_config('collector_token', collector_token, boto_secrets)
        base_config = merge_dicts(base_config, boto_secrets)
        json.dump(boto_secrets, open(args.new_secrets_file, 'w'), indent=6, sort_keys=True)

    instance_name = "dockerhp"
    instances_configs = {i['name']: i for i in boto_config.get('instance_descriptions', [])}
    command_string_parameters = instances_configs[instance_name].get('command_string_parameters', [])
    dc_command_format_args = command_strings_to_dict(command_string_parameters)
    dc_command_format_args = merge_dicts(dc_command_format_args, boto_secrets)
    max_count = args.dockerhp_count
    regions = args.dockerhp_regions
    if "all" in regions:
        regions = DCS

    region_processes = {}
    for region in regions:
        args = (instance_name, boto_config, "setup", dc_command_format_args, region, max_count, base_config)
        proc = Process(target=deploy_dockerhp_region, name=None, args=args)
        proc.start()
        region_processes[region] = proc

    LOGGER.info("Waiting for {} processes to complete".format(len(region_processes)))
    items = [(k, v) for k,v in region_processes.items()]
    while len(items) > 0:
        items = [(k, v) for k,v in region_processes.items() if v.is_alive()]
        LOGGER.info("Waiting for {} out of {} processes to complete.".format(len(items), len(region_processes)))
        if len(items) == 0:
            break
        sleep(60.0)
    LOGGER.info("Completed: {} deployment processes".format(len(region_processes)))
    return results

def deploy_dockerhp_region(instance_name, boto_config, setup_activity_name, 
                           command_format_args, region, max_count, base_config):
    rdc_ai = {}
    rdc_ipi = {}
    rdc_av = {}
    rdc_sr = {}
    results = {}
    results = {}
    threads = []
    try:
        dc_ai, dc_ipi, dc_av, dc_sr = build_instance_and_setup(instance_name, boto_config, setup_activity_name="setup", 
                                                   command_format_args=command_format_args, region=region, 
                                                   max_count=max_count)
        rdc_ai[region] = dc_ai
        rdc_ipi[region] = dc_ipi
        rdc_av[region] = dc_av
        rdc_sr[region] = dc_sr
        if dc_ipi is None:
            LOGGER.critical("Public IP information is None, meaning an error occurred somewhere, skipping: {}".format(region))
            return
        if dc_ai is None:
            LOGGER.critical("Instance information is None, meaning an error occurred somewhere, skipping: {}".format(region))
            return
        

        for iid in dc_ai:
            args = (instance_name, region, base_config, {iid: dc_ai[iid]}, {iid:dc_ipi[iid]}, command_format_args, boto_config)
            thread = Thread(target=handle_dockerhp_config_update_and_start, args=args)
            thread.start()
            threads.append(thread)
    except:
        LOGGER.critical("Exception occurred when trying to initialize instances in {}".format(region))
        LOGGER.critical(traceback.format_exc())

    LOGGER.info("Waiting for {} threads to complete for {}".format(len(threads), region))
    while len(threads) > 0:
        threads = [i for i in threads if i.is_alive()]
        LOGGER.info("Waiting for {} threads to complete for {}".format(len(threads), region))
        if len(threads) == 0:
            break
        sleep(60.0)
    LOGGER.info("Completed: {} threads to complete for {}".format(len(threads), region))
    return results

def deploy_collector(args, boto_config, boto_secrets):
    base_config = json.load(open(args.collector_config))
    base_config = merge_dicts(base_config, boto_secrets)
    # check mongo is valid
    if base_config.get("mongo", False):
        mongo_pass = base_config.get('mongo_pass', None)
        mongo_host = base_config.get('mongo_host', None)
        if mongo_pass is None:
            LOGGER.critical("Missing 'mongo_pass', exiting")
        elif mongo_host is None:
            LOGGER.critical("Missing 'mongo_host', exiting")
    
    if base_config.get("slack", False):
        if base_config.get("slack_webhook", None) is None:
            LOGGER.critical("Missing 'slack_webhook', exiting")

    if base_config.get("wbx", False):
        if base_config.get("wbx_webhook", None) is None:
            LOGGER.critical("Missing 'wbx_webhook', exiting")

    server_secret_key = base_config.get("server_secret_key", None)
    if server_secret_key is None:
        server_secret_key = random_alphanum_string_generator()
        update_config('server_secret_key', server_secret_key, boto_secrets)
        base_config = merge_dicts(base_config, boto_secrets)
        json.dump(boto_secrets, open(args.new_secrets_file, 'w'), indent=6, sort_keys=True)

    collector_token = boto_secrets.get('collector_token', None)
    if collector_token is None:
        collector_token = random_alphanum_string_generator()
        update_config('collector_token', collector_token, boto_secrets)
        base_config = merge_dicts(base_config, boto_secrets)
        json.dump(boto_secrets, open(args.new_secrets_file, 'w'), indent=6, sort_keys=True)

    instance_name = "dockerhp-collector"
    instances_configs = {i['name']: i for i in boto_config.get('instance_descriptions', [])}
    instance_config = instances_configs[instance_name]
    command_string_parameters = instance_config.get('command_string_parameters', [])
    dc_command_format_args = command_strings_to_dict(command_string_parameters)
    dc_command_format_args = merge_dicts(dc_command_format_args, boto_secrets)
    max_count = 1 if args.collector_count > 2 and args.collector_count < 1 else args.collector_count
    regions = [args.collector_region]
    region = args.collector_region
    rdc_ai, rdc_ipi, rdc_av, rdc_sr = build_instance_and_setup_multi_regions_count(instance_name, boto_config, 
                                                        regions, max_count, command_format_args=dc_command_format_args)
    
    dc_ai = rdc_ai[region]
    dc_ipi = rdc_ipi[region]
    dc_av = rdc_av[region]
    dc_sr = rdc_sr[region]
    
    collector_host = None
    alt_collector_host = None
    if len(dc_ipi) > 1:
        collector_host, alt_collector_host = [ip for ip in dc_ipi.values()][:2]
    else:
        collector_host = [ip for ip in dc_ipi.values()][0]
        alt_collector_host = collector_host

    update_config('collector_host', collector_host, boto_secrets)
    update_config('collector_alt_host', alt_collector_host, boto_secrets)
    base_config = merge_dicts(base_config, boto_secrets)
    dc_command_format_args = merge_dicts(dc_command_format_args, boto_secrets)
    json.dump(boto_secrets, open(args.new_secrets_file, 'w'), indent=6, sort_keys=True)
    json.dumps(dc_command_format_args, indent=6, sort_keys=True)
    handle_collector_config_update_and_start(instance_name, region, base_config, dc_ai, dc_ipi, dc_command_format_args, boto_config)

def deploy_mongodb(args, boto_config, boto_secrets):
    mongo_user = boto_secrets.get('mongo_user', None)
    mongo_pass = boto_secrets.get('mongo_pass', None)
    if mongo_user is None:
        update_config('mongo_user', 'mongo_user', boto_secrets)
        boto_config = merge_dicts(boto_config, boto_secrets)

    if mongo_pass is None:
        update_config('mongo_pass', random_alphanum_string_generator(), boto_secrets)
        boto_config = merge_dicts(boto_config, boto_secrets)
        mongo_pass = boto_secrets.get('mongo_pass', None)
    
    instance_name = "dockerhp-mongodb"
    instances_configs = {i['name']: i for i in boto_config.get('instance_descriptions', [])}
    instance_config = instances_configs.get(instance_name)
    command_string_parameters = instances_configs['dockerhp-mongodb'].get('command_string_parameters', [])
    mdb_command_format_args = command_strings_to_dict(command_string_parameters)
    merge_dicts(mdb_command_format_args, boto_secrets)
    regions = [args.mongodb_region]
    max_count = 1
    mdb_ai, mdb_ipi, mdb_av, mdb_sr = build_instance_and_setup_multi_regions_count(instance_name, boto_config, 
                                                                                   regions, max_count, command_format_args=mdb_command_format_args)
    mongo_host = list(mdb_ipi[args.mongodb_region].values())[0]
    update_config('mongo_host', mongo_host, boto_secrets)
    boto_config = merge_dicts(boto_config, boto_secrets)
    json.dump(boto_secrets, open(args.new_secrets_file, 'w'), indent=6, sort_keys=True)


def update_config(key, value, config):
    config[key] = value

if __name__ == "__main__":

    args = parser.parse_args()

    if args.config is None or args.secrets is None:
        parser.print_help()
        LOGGER.error("must provide a secrets and config file, exiting")
        sys.exit(-1)
    elif args.collector_up and \
         args.collector_config == 'internal-scripts/collector_config.json':
        try:
            os.stat(args.collector_config)
        except:
            LOGGER.error("invalid base collector config ({}), please create one or update the path, exiting".format(args.collector_config))
            parser.print_help()
            sys.exit(-1)
    elif args.dockerhp_up and \
         args.dockerhp_config == 'internal-scripts/hp_config.json':
        try:
            os.stat(args.collector_config)
        except:
            LOGGER.error("invalid base collector config ({}), please create one or update the path, exiting".format(args.collector_config))
            parser.print_help()
            sys.exit(-1)

    boto_config = json.load(open(args.config))
    boto_secrets = json.load(open(args.secrets))
    boto_config = merge_dicts(boto_config, boto_secrets)
    boto.Commands.set_config(**boto_config)

    for i in boto_config.get('instance_descriptions', []):
        i['recreate_keypair'] = args.recreate_keys
    

    do_down = []
    if args.mongodb_down:
        instance_down('mongodb', regions=[args.mongodb_region])
        do_down.append(['mongodb', [args.mongodb_region]])
    if args.collector_down:
        instance_down('collector', regions=[args.collector_region])
        do_down.append(['collector', [args.collector_region]])
    if args.dockerhp_down:
        _regions = args.dockerhp_regions
        if "all" in args.dockerhp_regions:
            _regions = DCS
        instance_down('dockerhp', regions=_regions)
        do_down.append(['dockerhp', args.dockerhp_regions])
    if args.mongodb_delete_vols:
        instance_down('mongodb_vols', regions=[args.mongodb_region])
        do_down.append(['mongodb_vols', [args.mongodb_region]])

    if len(do_down):
        LOGGER.info("Brought down the following instance types in the following regions:")
        for t, r in do_down:
            LOGGER.info("Type: {} Regions: {}".format(t, ",".join(r)))
        sys.exit(0)

    if args.mongodb_up:
        LOGGER.info("Deploying mongodb")
        deploy_mongodb(args, boto_config, boto_secrets)

    if args.collector_up:
        LOGGER.info("Deploying collector")
        deploy_collector(args, boto_config, boto_secrets)

    if args.dockerhp_up:
        LOGGER.info("Deploying dockerhp")
        deploy_dockerhp(args, boto_config, boto_secrets)
