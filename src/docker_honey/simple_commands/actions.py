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

from .consts import *
from .util import *
from . import boto
from . import ssh
import traceback
import json
import os
import time

import logging
ACTION_LOGGER = get_stream_logger(__name__)

command_strings_to_dict = lambda x: {i['name']: i['value'] for i in x}

def perform_activity(instance_name, all_instances, activity_name, 
                     instance_public_ip, boto_config, command_format_args, username=UBUNTU):
    # get instance config
    instances_configs = {i['name']: i for i in boto_config.get('instance_descriptions', [])}
    instance_config = instances_configs.get(instance_name)
    
    # get activities and actions for setup sequence
    instance_activities = instance_config.get('activities')
    activity = instance_activities.get(activity_name)
    all_actions = boto_config.get("actions")
    keypath = boto_config.get('ssh_key_path', '')
    # print(json.dumps(activity, sort_keys=True, indent=6),
    #     json.dumps(instance_activities, sort_keys=True, indent=6),
    #     activity_name)

    ssh_reqs = {} 
    for iid, iinfo in all_instances.items():
        key_filename = list(all_instances.values())[0]['KeyName']
        key_file = os.path.join(keypath, key_filename)
        ssh_reqs[iid] = {'key_file': key_file, 'host': instance_public_ip[iid], 'username': username}
    ACTION_LOGGER.info("Performing {} for {} ({} instances)".format(activity_name, instance_name, len(all_instances)))
    return perform_instance_activities(instance_name, all_instances, activity_name,  activity, 
                                       all_actions, ssh_reqs, command_format_args, boto_config)


def perform_instance_activities(instance_name:str, all_instances:dict, activity_name:str, 
                                activity: dict, all_actions:dict, ssh_reqs: dict,
                                command_format_args, boto_config):
    # iterate over the actions and then execut them.
    # FIXME multi threading required here
    # need to redo how results are managed and returned
    steps = activity.get('steps')
    activity_results = {'instance_name':instance_name,
                        'activity_name': activity_name, 
                        "step_results": [], 
                        "steps": steps,
                        "command_format_args": command_format_args}
    # print(activity_name, '\n', json.dumps(activity, indent=6, sort_keys=True))
    # print("all_actions", '\n', json.dumps(all_actions, indent=6, sort_keys=True))
    unpack_ssh_reqs = lambda reqs: (reqs['host'], reqs['key_file'], reqs['username']) 
    for action in steps:
        cactivity = all_actions.get(action, None)
        if cactivity is None:
            msg = "'{}' from '{}' activity steps ({}) is not a defined activity in the orchestration description."
            msg = msg.format(action, activity_name, steps)
            ACTION_LOGGER.critical(msg)
            raise Exception(msg)
        atype = cactivity.get('type')
        pre_wait = cactivity.get('pre_wait', 0.0)
        time.sleep(pre_wait)
        aresults = {'name': action,
                    'type':atype, 
                    "results":[], 
                    }

        if atype == 'commands':
            # create the command list
            commands = [i.format(**command_format_args) for i in cactivity.get('commands', [])]
            aresults["commands"] = commands
            # TODO execute the commands
            for instance_id, ssh_req in ssh_reqs.items():
                host, key_file, username = unpack_ssh_reqs(ssh_req)
                ACTION_LOGGER.debug("Performing {}:{} ({} elements) for {}@{} with {}".format(activity_name, atype, len(commands), username, host, key_file))
                result = ssh.Commands.execute_commands(commands, host=host, key_filename=key_file, username=username)
                outcome = {'instance_id': instance_id, "host": host, 'result': result}
                aresults["results"].append(outcome)
        elif atype == 'upload_files':
            dst_src = {}    
            for scp_args in cactivity.get('files', []):
                src = scp_args.get('src')
                dst = scp_args.get('dst')
                dst_src[dst] = src
            aresults["dst_src_files"] = dst_src
            # scp the files over
            for instance_id, ssh_req in ssh_reqs.items():
                ACTION_LOGGER.debug("Performing {}:{} ({} elements) for {}@{} with {}".format(activity_name, atype, len(dst_src), username, host, key_file))
                host, key_file, username = unpack_ssh_reqs(ssh_req)
                result = ssh.Commands.upload_files(dst_src, host=host, key_filename=key_file, username=username)
                outcome = {'instance_id': instance_id, "host": host, 'result': result}
                aresults["results"].append(outcome)
            activity_results['step_results'].append(aresults)
        elif atype == "boto":
            aresults["command_parameters"] = cactivity.get('command_parameters', [])
            aresults["commands"] = cactivity.get('commands', [])
            # scp the files over
            for instance_id, ssh_req in ssh_reqs.items():
                host, key_file, username = unpack_ssh_reqs(ssh_req)
                ACTION_LOGGER.debug("Invalid activity {}:{} for {}@{} with {}".format(activity_name, atype, username, host, key_file))
                outcome = {'instance_id': instance_id, "host": host, 'result': "Unsupported action"}
                aresults["results"].append(outcome)
            activity_results['step_results'].append(aresults)
        else:
            for instance_id, ssh_req in ssh_reqs.items():
                host, key_file, username = unpack_ssh_reqs(ssh_req)
                ACTION_LOGGER.debug("Invalid activity {}:{} for {}@{} with {}".format(activity_name, atype, username, host, key_file))
                outcome = {'instance_id': instance_id, "host": host, 'result': "Unsupported action"}
                aresults["results"].append(outcome)
            activity_results['step_results'].append(aresults)
        post_wait = cactivity.get('post_wait', 0.0)
        time.sleep(post_wait)            
    return activity_results


def build_instance_and_setup(instance_name, config, setup_activity_name="setup", command_format_args: dict=None, region=None, max_count=None):
    #initialize the boto command
    ACTION_LOGGER.debug("Initializing the boto.Commands klass".format())
    boto.Commands.set_config(**config)

    # get instance config
    instances_configs = {i['name']: i for i in config.get('instance_descriptions', [])}
    instance_config = instances_configs.get(instance_name)
    
    # prep format arguments for env
    config_command_format_args = command_strings_to_dict(instance_config.get('command_string_parameters', []))
    command_format_args = command_format_args if isinstance(command_format_args, dict) and len(command_format_args) else {}
    
    config_command_format_args.update(command_format_args)
    command_format_args = config_command_format_args
    # get activities and actions for setup sequence
    instance_activities = instances_configs.get('activities')
    all_actions = config.get('actions')
    
    
    # ssh key stuff
    username = instance_config.get('username', UBUNTU)
    keypath = config.get('ssh_key_path', '')
    
    # use the config to set up the hosts
    ACTION_LOGGER.info("Creating {} instances in {} for '{}'".format(max_count, region, instance_name))
    all_instances, all_volumes = boto.Commands.build_instance_region(region, instance_name, config, max_count=max_count)
    ACTION_LOGGER.info("Created {} instances and {} volumes for '{}' in {}".format(len(all_instances), len(all_volumes), instance_name, region))
    instance_public_ip = boto.Commands.get_instance_public_ips([i for i in all_instances], **config)
    
    # create path to ssh key
    key_filename = list(all_instances.values())[0]['KeyName']
    key_file = os.path.join(keypath, key_filename)
    
    # perform setup activity
    setup_results = None
    ACTION_LOGGER.info("Setting-up {} instances and {} volumes for '{}' in {} with activity: '{}'".format(len(all_instances), len(all_volumes), instance_name, region, setup_activity_name))
    try:
        setup_results = perform_activity(instance_name, all_instances, setup_activity_name, instance_public_ip, config, command_format_args)
    except:
        ACTION_LOGGER.info("Failed setup: {} ".format(traceback.format_exc()))
    return all_instances, instance_public_ip, all_volumes, setup_results

def build_instance_and_setup_multi_regions_count(instance_name, config, regions, max_count, command_format_args=None, setup_activity_name="setup"):
    #initialize the boto command
    boto.Commands.set_config(**config)
    all_instances = {}
    all_volumes = {}
    instance_id_key = {}
    keypath = config.get('ssh_key_path', '')
    backup_config = config.copy()
    
    all_instances = {}
    instance_public_ip = {}
    all_volumes = {}
    setup_results = {}

    for region in regions:
        try:
            ai, ipi, av, sr = build_instance_and_setup(instance_name, config, setup_activity_name=setup_activity_name, 
                                                       command_format_args=command_format_args, region=region, 
                                                       max_count=max_count)
        except:
            ACTION_LOGGER.critical("Exception occurred when trying to initialize instances in {}".format(region))
            ACTION_LOGGER.critical(traceback.format_exc())
            all_instances[region] = None
            instance_public_ip[region] = None
            all_volumes[region] = None
            setup_results[region] = None
            continue
        all_instances[region] = ai
        instance_public_ip[region] = ipi
        all_volumes[region] = av
        setup_results[region] = sr

    return all_instances, instance_public_ip, all_volumes, setup_results
