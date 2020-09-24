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
import boto3
from .consts import *
from .util import *
import traceback
import time

class Commands(object):
    AWS_SECRET_ACCESS_KEY = None
    AWS_ACCESS_KEY_ID = None
    CURRENT_REGION = 'us-east-2'

    KMS_KEYS = {}
    KMS_ARNS = {}
    KMS_INFOS = {}
    KMS_ALIASES = {}

    DEFAULT_KMS_IDS = {}
    DEFAULT_KMS_ALIASES = {}
    DEFAULT_KMS_ARNS = {}
    REGIONS = [CURRENT_REGION]
    LOGGER = get_stream_logger(__name__ + '.Commands')
    IMAGE_CATALOG = {}
    IMAGE_AMI_IDS = {}
    IMAGE_AMI_NAMES = {}

    @classmethod
    def get_image_infos(cls, region, **kargs):
        cls.set_region(region)
        if region in cls.IMAGE_CATALOG:
            return cls.IMAGE_CATALOG[region]

        ec2 = cls.get_ec2(**kargs)
        cls.LOGGER.info("Getting AMI info {} for all images".format(region))
        rsp = ec2.describe_images()
        cls.IMAGE_CATALOG[region] = []
        image_datas = rsp['Images']
        for image_data in image_datas:
            image_info = {
                "image_architecture": image_data.get('Architecture', '').lower(),
                "image_platform_details": image_data.get('PlatformDetails', '').lower(),
                "image_public": image_data.get('Public', False),
                "image_name": image_data.get('Name', '').lower(),
                "image_type": image_data.get('ImageType', '').lower(),
                "image_description": image_data.get('Description', '').lower(),
                "image_id": image_data.get('ImageId', '').lower(),
                "image_state": image_data.get('State', '').lower(),
                "image_block_mappings": image_data.get('BlockDeviceMappings', []),
                "image_owner_alias": image_data.get('ImageOwnerAlias', '').lower(),
                "image_creation_date": image_data.get('CreationDate', ''),
                "image_owner_id": image_data.get('OwnerId', '').lower(),
                "image_virtualization_type": image_data.get('VirtualizationType', '').lower(),
            }
            cls.IMAGE_CATALOG[region].append(image_info)
        cls.IMAGE_AMI_IDS[region] = {i['image_id']:i for i in cls.IMAGE_CATALOG[region]}
        cls.IMAGE_AMI_NAMES[region] = {i['image_name']:i for i in cls.IMAGE_CATALOG[region]}
        return sorted(cls.IMAGE_AMI_NAMES[region].values(), reverse=True, key=lambda x:x["image_creation_date"])

    @classmethod
    def extract_ami_paramaters(cls, instance_config):
        parameters = {
            "image_architecture": instance_config.get('image_architecture', None),
            "image_platform_details": instance_config.get('platform_details', None),
            "image_public": instance_config.get('image_public', True),
            "image_name": instance_config.get('image_name', None),
            "image_image_type": instance_config.get('image_type', None),
            "image_description_keywords": instance_config.get('image_description_keywords', None),
            "image_image_id": instance_config.get('image_id', None),
            "image_owner_alias": instance_config.get('image_owner_alias', None),
            "image_owner_id": instance_config.get('image_owner_id', None),
            "image_virtualization_type": instance_config.get('image_virtualization_type', "hvm"),
        }
        if isinstance(parameters["image_description_keywords"], list) and len(parameters["image_description_keywords"]) > 0:
            parameters["image_description_keywords"] = [i.lower() for i in parameters["image_description_keywords"]] 
        else:
            parameters["image_description_keywords"] = None
        return {k:v if not isinstance(v, str) else v.lower() for k, v in parameters.items() if v is not None or (isinstance(v, str) and len(v) > 0)}

    @classmethod
    def match_description(cls, keywords, description, any_words=False):
        if any_words:
            return any([description.find(w) > -1 for w in keywords])
        return all([description.find(w) > -1 for w in keywords])

    @classmethod
    def find_matching_images(cls, ami_info, image_infos, match_keys=MATCH_KEYS, 
                             match_desc=True):

        match_these = {k: ami_info[k] for k in match_keys if k in ami_info and ami_info[k] is not None}
        keywords = ami_info.get('image_description_keywords', None)
        if keywords is None and match_desc:
            cls.LOGGER.critical("No keyword provided to match a AMI".format())
            raise Exception("No keyword provided to match a AMI".format())

        others_good = []
        for amii in image_infos:
            desc = amii.get('image_description', '')
            if (desc is None or len(desc) == 0) and match_desc:
                continue

            all_matches = []
            for k in match_these:
                if amii.get(k, None) is None:
                    continue
                all_matches.append(match_these[k] == amii[k])

            if all(all_matches):
                others_good.append(amii)
        
        if not match_desc:
            return [i['image_id'] for i in others_good]

        good_desc = []
        for ii in others_good:
            desc = ii.get('image_description', '')
            if cls.match_description(keywords, desc):
                good_desc.append(ii)

        return [i['image_id'] for i in good_desc]
    
    @classmethod
    def get_image_id(cls, instance_name, region, boto_config, any_words=False, return_one=True):
        cls.set_region(region)
        instance_description = cls.get_instance_description(instance_name, boto_config)
        ami_info = cls.extract_ami_paramaters(instance_description)
        ami_id = ami_info.get('image_id', None)
        ami_name = ami_info.get('image_name', None)

        ami_id = ami_id if isinstance(ami_id, str) and len(ami_id) > 0 else None
        ami_name = ami_name if isinstance(ami_name, str) and len(ami_name) > 0 else None
        if ami_name is not None and ami_name in cls.IMAGE_AMI_NAMES[region]:
            ami_id = cls.IMAGE_AMI_NAMES[region]['image_id']

        if ami_id is not None and ami_id in cls.IMAGE_AMI_IDS[region]:
            cls.LOGGER.info("Using AMI image Id ({}) in {}".format(ami_id, ami_region))
            return ami_id
            
        image_infos = cls.get_image_infos(region, **boto_config)
        keywords = ami_info.get('image_description_keywords', None)
        matching_images = cls.find_matching_images(ami_info, image_infos)

        if len(matching_images) > 0 and return_one:
            return matching_images[0]
        elif len(matching_images) > 0:
            return matching_images
        cls.LOGGER.critical("Unable to identify an AMI image Id in {}".format(region))
        raise Exception("Unable to identify an AMI image Id in {}".format(region))

    @classmethod
    def get_instance_type(cls, instance_name, boto_config):
        instance_description = cls.get_instance_description(instance_name, boto_config)
        if 'instance_type' in instance_description:
            return instance_description['instance_type']
        return boto_config.get('instance_type', 't2.micro')

    @classmethod
    def get_instance_key_info(cls, instance_name, config, **kargs):
        instance_config = cls.get_instance_description(instance_name, config)
        base_keyname = instance_config.get('base_keyname', 'aws-instance-key')
        keyname_fmt = instance_config.get('keyname_fmt', "{base_keyname}.pem")

        _kargs = kargs.copy()
        _kargs['base_keyname'] = base_keyname
        key_info = {
            'key_path': config.get('ssh_key_path', './ssh_keys/'),
            'key_name': keyname_fmt.format(**_kargs),
            'recreate': instance_config.get('recreate_keypair', False)   
        }
        return key_info

    @classmethod
    def create_tag_specs(cls, resource_type,  tags, tag_config_type='key_value'):
        tag_spec = None
        if tag_config_type == 'raw':
            tag_spec = tags
        elif tag_config_type == 'key_value':
            tag_spec = {'ResourceType': resource_type,
                        'Tags': [{'Key':k, 'Value': v} for k, v in tags.items()]
                        }
        return tag_spec

    @classmethod
    def get_tag_specs_configs(cls, boto_config, tag_specs=None, tag_specs_names=None, resource_type='instance'):
        if tag_specs is None:
            tag_specs = boto_config.get('tag_specs', [])
        if tag_specs_names and len(tag_specs_names) > 0:
            tag_specs = [i for i in tag_specs if i['name'] in tag_specs_names]
        
        tag_specifications = []
        for tag_config in tag_specs:
            rtype = tag_config.get('resource_type', resource_type)
            if rtype != resource_type:
                continue
            tags = tag_config.get('tags', {})
            tag_config_type = tag_config.get('tag_config_type', 'key_value')
            if rtype:
                tag_specifications.append(cls.create_tag_specs(rtype, tags, tag_config_type))
        return tag_specifications

    @classmethod
    def get_instance_description(cls, instance_name, boto_config):
        configs = boto_config.get('instance_descriptions', [])
        for config in configs:
            x = config.get('name', None)
            if x and x == instance_name:
                return config
        return {}

    @classmethod
    def get_instance_names(cls, boto_config):
        configs = boto_config.get('instance_descriptions', [])
        names = []
        for config in configs:
            x = config.get('name', None)
            if x:
                names.append(x)
        return names

    @classmethod
    def get_instance_descriptions(cls, boto_config):
        configs = boto_config.get('instance_descriptions', [])
        iconfigs = {}
        for config in configs:
            x = config.get('name', None)
            if x:
                iconfigs[x] = config
        return iconfigs

    @classmethod
    def get_instance_config_elements(cls, instance_name, element, boto_config):
        description = cls.get_instance_description(instance_name, boto_config)
        if description is None:
            return None
        citems = boto_config.get(element, [])
        configs = []
        instance_items = description.get(element, [])
        for item in citems:
            if 'name' in item and item['name'] in instance_items:
                configs.append(item)
        return configs

    @classmethod
    def get_volume_tags_configs(cls, volume_name, boto_config):
        tag_spec_names = boto_config.get('volumes', {}).get(volume_name, {}).get('tag_specs', None)
        if tag_specs_names:
            return cls.get_tag_specs_configs(config, tag_specs_names=tag_spec_names, resource_type='volume')
        return None

    @classmethod
    def get_volume_description(cls, volume_name, boto_config):
        volume_configs = boto_config.get('volumes', [])
        if len(volume_configs) == 0:
            return None
        vcs = cls.get_volume_descriptions(boto_config)
        return vcs.get(volume_name, None)

    @classmethod
    def get_volume_descriptions(cls, boto_config):
        volume_configs = boto_config.get('volumes', [])
        if len(volume_configs) == 0:
            return None
        return {config.get('name'): config for config in volume_configs if 'name'}

    @classmethod
    def get_volume_device_descriptions(cls, instance_name, volume_names, boto_config):
        volume_names = [] if not isinstance(volume_names, list) else volume_names
        instance_config = cls.get_instance_description(instance_name, boto_config)
        device_configs = instance_config.get('volume_devices', [])
        return device_configs

    @classmethod
    def get_instance_security_group_configs(cls, instance_name, boto_config):
        return cls.get_instance_config_elements(instance_name, 'security_groups', boto_config)

    @classmethod
    def get_instance_tag_specifications(cls, instance_name, boto_config):
        instance_config = cls.get_instance_description(instance_name, boto_config)
        
        tag_specs_names = instance_config.get('tag_specs', None)
        if tag_specs_names:
            return cls.get_tag_specs_configs(boto_config, tag_specs_names=tag_specs_names, resource_type='instance')
        return None


    @classmethod
    def get_instance_volumes_configs(cls, instance_name, boto_config):
        return cls.get_instance_config_elements(instance_name, 'volumes', boto_config)

    @classmethod
    def get_instance_security_group(cls, instance_name, boto_config):
        description = cls.get_instance_description(instance_name, boto_config)
        if description is None:
            return None
        sgs = boto_config.get('security_groups', [])
        sg_config = []
        instance_sgs = description.get('security_groups', [])
        for sg in sgs:
            if 'name' in sg and sg['name'] in instance_sgs:
                sg_config.append(sg)
        return sg

    @classmethod
    def set_config(cls, **kargs):
        cls.AWS_ACCESS_KEY_ID = kargs.get('aws_access_key_id', None)
        cls.AWS_SECRET_ACCESS_KEY= kargs.get('aws_secret_access_key', None)
        cls.REGIONS = kargs.get('regions', cls.REGIONS) 
        cls.REGIONS = kargs.get('regions', cls.REGIONS) 
        # cls.update_current_kms_defaults(**kargs)

    @classmethod
    def create_tags_keywords(cls, *extra_args):
        tags = {}
        for k,v in zip(extra_args[::2],extra_args[1::2]):        
            key = None
            if k.startswith(TAG_MARKER):
                key = k[len(TAG_MARKER):]
            else:
                continue
            key = key.replace('-','_')
            tags[key] = v
        return tags

    @classmethod
    def set_region(cls, region, **kargs):
        if region is not None and region != cls.CURRENT_REGION:
            cls.CURRENT_REGION = region

    @classmethod
    def get_region(cls):
        return cls.CURRENT_REGION

    @classmethod
    def get_current_region(cls):
        return cls.CURRENT_REGION        


    @classmethod
    def get_ec2(cls, ec2=None, region=None, aws_secret_access_key=None, aws_access_key_id=None, **kargs):
        if region is None:
            region = cls.get_current_region()


        if ec2 is None:
            # cls.LOGGER.debug("Creating ec2 client for {} in {}".format(region, aws_access_key_id))
            aws_secret_access_key = aws_secret_access_key if aws_secret_access_key else cls.AWS_SECRET_ACCESS_KEY
            aws_access_key_id = aws_access_key_id if aws_access_key_id else cls.AWS_ACCESS_KEY_ID
            ec2 = boto3.client('ec2', 
                           region, 
                           aws_access_key_id=aws_access_key_id, 
                           aws_secret_access_key=aws_secret_access_key)
        return ec2

    @classmethod
    def get_kms_key(cls, kms=None, region=None, aws_secret_access_key=None, aws_access_key_id=None,
                    key_name=None, key_id=None, **kargs):

        if key_name is None and key_id is None:
            if cls.DEFAULT_KMS_IDS[region]:
                return cls.DEFAULT_KMS_IDS[region]

            kms = cls.get_kms(region=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        return kms

    @classmethod
    def update_current_kms_defaults(cls, region=None, **kargs):
        # FIXME this code is unreliable when switching between regions
        # TODO this is all wrong and does not take into 
        # account when regions change, because the keys will also change
        # with the given region

        kms = cls.get_kms(region=region, **kargs)
        
        aliases = kms.list_aliases()
        rsp = kms.list_keys()

        cls.DEFAULT_KMS_IDS[region] = None
        cls.KMS_ALIASES[region] = aliases['Aliases']
        cls.KMS_KEYS[region] = {k['KeyId']: k for k in rsp['Keys']}
        cls.KMS_ARNS[region] = {k['KeyId']: k['KeyArn'] for k in rsp['Keys']}

        cls.KMS_INFOS[region] = {}
        for kid in cls.KMS_KEYS:
            cls.KMS_INFOS[region][kid] = kms.describe_key(KeyId=kid)

        alias_name = cls.DEFAULT_KMS_ALIAS if cls.DEFAULT_KMS_ALIAS else 'alias/aws/ebs'
        for alias in cls.KMS_ALIASES[region]:
            if alias['AliasName'] == alias_name:
                cls.DEFAULT_KMS_IDS[region] = alias['TargetKeyId']
                cls.DEFAULT_KMS_ALIASES[region] = alias['AliasName']
                break

        if cls.DEFAULT_KMS_IDS[region] is None:
            cls.DEFAULT_KMS_IDS[region] = list(all_keys.keys())[0]
            cls.DEFAULT_KMS_ALIASES[region] = "None"
            cls.DEFAULT_KMS_ARNS[region] = cls.KMS_ARNS[region][cls.DEFAULT_KMS_IDS[region]]
        else:
            cls.DEFAULT_KMS_ARNS[region] = cls.KMS_ARNS[region][cls.DEFAULT_KMS_IDS[region]]

    @classmethod
    def get_default_kms_key(cls, region=None, **kargs):
        if cls.DEFAULT_KMS_IDS[region] is None:
            cls.update_current_kms_defaults(region=region, **karg)
        return {'alias':cls.DEFAULT_KMS_ALIASES[region], 
                'keyarn':cls.DEFAULT_KMS_ARNS[region], 
                'keyid':cls.DEFAULT_KMS_IDS[region]}

    @classmethod
    def check_kms_key(cls, key_arn=None, key_id=None, region=None, **kargs):
        cls.LOGGER.debug("checking key: arn={}, id={}".format(key_arn, key_id))
        info = cls.get_kms_key(region=region, key_arn=key_arn, key_id=key_id, **kargs)
        return not info is None

    @classmethod
    def recreate_kms_key(cls, tags=None, region=None, **kargs):
        kms = cls.get_kms(region=region, **kargs)
        cls.LOGGER.info("creating a new kms key".format(key_arn, key_id))
        # TODO add tags
        _kargs = {}
        if tags:
            _kargs['Tags'] = tags

        x = kms.create_key(**tags)
        y = x['KeyMetadata']
        return {'alias':"None", 
                'keyarn':y['Arn'], 
                'keyid':y['KeyId']}
    
    @classmethod
    def create_kms_key(cls, region, tags=None, **kargs):
        kms = cls.get_kms(region=region, **kargs)
        cls.LOGGER.info("creating a new kms key".format(key_arn, key_id))
        # TODO add tags
        _kargs = {}
        if tags:
            _kargs['Tags'] = tags

        x = kms.create_key(**tags)
        y = x['KeyMetadata']
        cls.KMS_KEYS[region][y['KeyId']] = y
        cls.KMS_ARNS[region][y['KeyId']] = y['Arn']
        cls.KMS_ARNS[region][y['KeyId']] = kms.describe_key(KeyId=y['KeyId'])
        return {'alias':"None", 
                'keyarn':y['Arn'], 
                'keyid':y['KeyId']}

    @classmethod
    def get_kms_key(cls, region, key_arn=None, key_id=None, create=False, **kargs):
        cls.LOGGER.info("geting a kms key: arn={}, id={} create={}".format(key_arn, key_id, create))
        if key_arn is None and key_id is None and create:
            return cls.create_kms_key(region, **kargs)
        
        dft_key_id = None if region not in cls.DEFAULT_KMS_IDS else cls.DEFAULT_KMS_IDS[region]
        dft_key_arn = None if region not in cls.DEFAULT_KMS_ARNS else cls.DEFAULT_KMS_ARNS[region]
        if key_id and dft_key_id and dft_key_id == key_id or \
           key_arn and dft_key_arn and dft_key_arn == key_arn:
            return cls.get_default_kms_key(region=region, **kargs)

        if key_id is None and key_arn is None:
            return cls.get_default_kms_key(region=region, **kargs)
        
        if region not in cls.KMS_KEYS:
            cls.update_current_kms_defaults(region=region, **kargs)
        setit = False
        if key_id:
            all_keys = cls.KMS_KEYS
            key_arn = all_keys.get(key_id, None)
            setit = key_id in all_keys
        else:
            all_keys = {v:k for k,v in cls.KMS_ARNS.items()}
            key_id = all_keys.get(key_arn, None)
            setit = key_arn in all_keys
        
        if setit:
            return {'alias':"None", 
                    'keyarn':key_arn, 
                    'keyid':key_id}
        elif create:
            return cls.create_kms_key(region, **kargs)
        cls.LOGGER.info("Failed to get a kms key: arn={}, id={} create={}".format(key_arn, key_id, create))
        return None

    @classmethod
    def get_default_aws_key_id(cls, region=None, **kargs):
        aliases = kms.list_aliases()
        update_current_kms_defaults(region=region, **kargs)
        kms = cls.get_kms(region=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        aliases = cls.DEFAULT_KMS_ALIASES[region]
        alias_name = cls.DEFAULT_KMS_ALIAS
        alias_key_id = cls.DEFAULT_KMS_IDS[region]
        if alias_key_id is not None and alias_name is not None:
            return kms.describe_key(KeyId=cls.DEFAULT_KMS_IDS[region])
        if cls.DEFAULT_KMS_IDS[region]:
            for alias in aliases['Aliases']:
                if 'TargetKeyId' in alias and alias['TargetKeyId'] == alias_key_id:
                    cls.DEFAULT_KMS_IDS[region] = alias['TargetKeyId']
                    cls.DEFAULT_KMS_ALIASES[region] = alias['AliasName']
                    break
        else:
            for alias in aliases['Aliases']:
                if alias['AliasName'] == alias_name:
                    cls.DEFAULT_KMS_IDS[region] = alias['TargetKeyId']
                    cls.DEFAULT_KMS_ALIASES[region] = alias['AliasName']
                    break
        if cls.DEFAULT_KMS_IDS[region]:
            return kms.describe_key(KeyId=cls.DEFAULT_KMS_IDS[region])
        return None

    @classmethod
    def get_kms(cls, kms=None, region=None, aws_secret_access_key=None, aws_access_key_id=None, **kargs):
        need_update = region == cls.get_current_region()
        if kms is None:
            cls.LOGGER.debug("Creating ec2 client for {} in {}".format(region, aws_access_key_id))
            aws_secret_access_key = aws_secret_access_key if aws_secret_access_key else cls.AWS_SECRET_ACCESS_KEY
            aws_access_key_id = aws_access_key_id if aws_access_key_id else cls.AWS_ACCESS_KEY_ID
            kms = boto3.client('kms', 
                           region, 
                           aws_access_key_id=aws_access_key_id, 
                           aws_secret_access_key=aws_secret_access_key)
        if need_update:
            cls.update_current_kms_defaults(region=region, **kargs)

        return kms

    @classmethod
    def delete_key_pair(cls, keyname, **kargs):
        ec2 = cls.get_ec2(**kargs)
        try:
            cls.LOGGER.info("Deleting keypair: {}".format(keyname))
            ec2.delete_key_pair(KeyName=keyname)
        except:
            raise

    @classmethod
    def get_key_pair(cls, key_name, key_path, recreate=False, region=None, **kargs):
        ec2 = cls.get_ec2(region=region, **kargs)
        key_filename = os.path.join(key_path, key_name)
        if not os.path.exists(key_path):
            cls.LOGGER.debug("Creating key directory: {}".format(key_path))
            os.makedirs(key_path, exist_ok=True)
        cls.LOGGER.debug("{} will be used.".format(key_filename))
        # keyfile not present but key in aws        
        if not os.path.exists(key_filename.strip('./')) and not recreate:
            key_pair_exists = False
            try:
                ec2.describe_key_pairs(KeyNames=[key_name])
                key_pair_exists = True
                cls.LOGGER.critical("Requested: {} but the private keys were present in AWS not found LOCALLY.".format(key_name))
                raise Exception("Requested: {} but the private keys were present in AWS not found LOCALLY.".format(key_name))
            except:
                if key_pair_exists:
                    raise
        # keyfile is present and key in should be in aws
        elif os.path.exists(key_filename.strip('./')) and not recreate:
            try:
                ec2.describe_key_pairs(KeyNames=[key_name])
                return key_filename
            except:
                cls.LOGGER.critical("Requested: {} but the private keys were present in LOCALLY not found AWS.".format(key_name))
                raise Exception("Requested: {} but the private keys were present in LOCALLY not found AWS.".format(key_name))

        elif recreate:
            cls.LOGGER.debug("Deleting key from ec2: {}".format(key_name))
            try:
                cls.delete_key_pair(keyname=key_name, ec2=ec2)
                cls.LOGGER.info("Deleted key from ec2: {}".format(key_name))
            except:
                pass

            try:
                os.remove(key_filename)
                cls.LOGGER.info("Deleted key file from disk: {}".format(key_filename))
            except:
                pass

        cls.LOGGER.info("Creating keypair: {}".format(key_name))
        key_pair = ec2.create_key_pair(KeyName=key_name)
        cls.LOGGER.info("Writing key file to disk: {}".format(key_filename))
        outfile = open(key_filename,'w')
        KeyPairOut = str(key_pair['KeyMaterial'])
        outfile.write(KeyPairOut)
        outfile.close()
        os.chmod(key_filename, 0o600)
        return key_filename

    @classmethod
    def delete_security_group(cls, sg_name=None, sg_id=None, **kargs):
        ec2 = cls.get_ec2(**kargs)
        _kargs = {}
        if sg_id:
            cls.LOGGER.info("Deleting Security Group ID: {}".format(sg_id))
            _kargs['GroupId'] = sg_name
        elif sg_name:
            cls.LOGGER.info("Deleting Security Group: {}".format(sg_name))
            _kargs['GroupName'] = sg_name
        else:
            return False
        try:
            rsp = ec2.delete_security_group(**_kargs)
            cls.LOGGER.info("Deleted Security Group".format())
            return True
        except:
            pass
        return False

    @classmethod
    def create_security_group(cls, sg_name, sg_description, ingress, refresh=False, **kargs):
        ec2 = cls.get_ec2(**kargs)
        try:
            rsp = ec2.describe_security_groups(GroupNames=[sg_name])
            sg_id = rsp['SecurityGroups'][0]['GroupId']
            if not refresh:
                return rsp['SecurityGroups'][0]['GroupId']
            cls.delete_security_group(sg_name=sg_name, sg_id=sg_id, ec2=ec2, **kargs)
        except:
            pass

        cls.LOGGER.info("Creating Security Group: {}".format(sg_name))
        rsp = ec2.create_security_group(GroupName=sg_name,
                                             Description=sg_description)
        sg_id = rsp.get('GroupId', None)
        if sg_id is None:
            raise Exception("Unable to create the security group")
        cls.LOGGER.info("Updating Security Group {} ingress rules".format(sg_id))
        ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ingress)
        return sg_id

    @classmethod
    def create_instances(cls, key_name, max_count, image_id, instance_type, security_groups, 
                         tag_specifications, availability_zone, do_hibernate=False, device_name='/dev/sda1', 
                         delete_on_termination=True, volume_size=20, volumetype='gp2', encrypted=False,
                         kms_key_id=None, kms_arn_id=None, create_volume=True, snapshotid=None, region=None, **kargs):
        
        ec2 = cls.get_ec2(region=region, **kargs)
        placement = None

        if availability_zone is not None:
            placement = {'AvailabilityZone': availability_zone}
        
        _kargs = {}
        block_info = None
        ebs = {
            'Encrypted': encrypted
        }
        if do_hibernate and any([instance_type.find(it) == 0 for i in HIBERNATEABLE]):
            _kargs['HibernationOptions'] = {'Configured': True}
            ebs['Encrypted'] = True

        if create_volume:
            ebs.update({
                'DeleteOnTermination': delete_on_termination,
                'VolumeSize': volume_size,
                'VolumeType': volumetype,
            })
            block_info = { 
                'DeviceName': device_name,
                'Ebs': ebs 
            }
            if ebs['Encrypted']:
                info = cls.get_kms_key(region=region, kms_key_id=kms_key_id, key_arn=kms_key_arn, create=True, tags=tags, **kargs)
                keyid = None
                if info is None:
                    keyid = info['keyid']
                ebs.update({
                    'KmsKeyId': keyid
                })
            if ebs['Encrypted'] and ebs['KmsKeyId'] is None:
                cls.LOGGER.critical("No valid key used for the encrypted volume")
                raise Exception("No valid key used for the encrypted volume")

            if snapshotid:
                ebs['SnapshotId'] = snapshotid
                del ebs['VolumeSize']
            _kargs['BlockDeviceMappings'] = [block_info,]

        _kargs.update({
            "DryRun":False, 
            "MinCount":1, 
            "MaxCount":max_count, 
            "ImageId":image_id, 
            "KeyName":key_name, 
            "InstanceType":instance_type, 
            "SecurityGroupIds":security_groups, 
            "TagSpecifications":tag_specifications,
            "Placement":placement,
        })
        
        del_keys = [i for i,v  in _kargs.items() if v is None ]
        for k in del_keys:
            del _kargs[k]

        cls.LOGGER.info("Starting {} '{}' instances in with {} ".format(max_count, instance_type, key_name))
        reservations = ec2.run_instances(**_kargs) 

        instances = [i['InstanceId'] for i in reservations['Instances']]
        if len(instances) > 0:
            r = ec2.describe_instances(InstanceIds=instances)
            instance_infos = []
            for k in r['Reservations']:
                instance_infos = instance_infos + k['Instances']
            t = {k['InstanceId']: k for k in instance_infos }
            return t
        return None

    @classmethod
    def create_security_groups(cls, security_group_configs, boto_config):
        sg_ids = []
        for sg in security_group_configs:
            sg_name = sg.get("name", None)
            sg_description = sg.get("description", None)
            ingress = sg.get("permissions", None)
            refresh = sg.get('refresh', False)
            sg_id = cls.create_security_group(sg_name, sg_description, ingress, 
                                              refresh=refresh, **boto_config)
            if sg_id:
                sg_ids.append(sg_id)
        return sg_ids

    @classmethod
    def wait_for_instances(cls, instance_ids, **kargs):
        ec2 = cls.get_ec2(**kargs)
        loaded_instances = None
        cls.LOGGER.info("Waiting for {} instances to be reachable".format(len(instance_ids)))
        while True:
            loaded_instances = cls.check_for_instances_up(instance_ids)
            if len(loaded_instances) == 0:
                time.sleep(5.0)
            elif len(loaded_instances) == len(instance_ids):
                break
            else:
                time.sleep(10.0)
        cls.LOGGER.info("{} instances are available".format(len(instance_ids)))
        return cls.get_instances(instance_ids=[i for i in loaded_instances])

    @classmethod
    def wait_for_volumes(cls, volume_ids, **kargs):
        ec2 = cls.get_ec2(**kargs)
        statuses = None
        cls.LOGGER.info("Waiting for {} volumes to be available".format(len(volume_ids)))
        while True:
            if len(volume_ids) == 0:
                break
            # print(instance_ids)
            rsp = ec2.describe_volumes(VolumeIds=volume_ids)
            # print(rsp)
            statuses = {i['VolumeId']: i for i in rsp['Volumes']}
            if len(statuses) == 0:
                time.sleep(5.0)
            elif all([i['State'] == 'available' for i in statuses.values()]):
                break
            else:
                time.sleep(10.0)
        cls.LOGGER.info("{} volumes are available".format(len(volume_ids)))
        return statuses

    @classmethod
    def build_instance_region(cls, region, instance_name, boto_config, max_count=None):
        cls.set_region(region)
        ec2 = cls.get_ec2(**boto_config)
        region = region if region else cls.get_current_region()
        instance_config = cls.get_instance_description(instance_name, boto_config)
        if len(instance_config) == 0:
            raise Exception("Incomplete instance configurations")
        max_count = max_count if max_count else instance_config.get('max_count', 1)

        cls.LOGGER.info("Creatinng {} instances for '{}' in {}".format(max_count, instance_name, region))
        instance_sg_configs = cls.get_instance_security_group_configs(instance_name, boto_config)
        instance_volume_configs = cls.get_instance_volumes_configs(instance_name, boto_config)

        instance_tag_specifigations = cls.get_instance_tag_specifications(instance_name, boto_config)

        # create keys
        key_info = cls.get_instance_key_info(instance_name, boto_config, region=region)
        key_name = key_info.get("key_name", None)
        key_filename = cls.get_key_pair(key_info['key_name'], key_info['key_path'], 
                                        recreate=key_info['recreate'], region=region, **boto_config)
        # create security groups
        security_groups = cls.create_security_groups(instance_sg_configs, boto_config)

        # create instance
        max_count = max_count if max_count else instance_config.get('max_count', 1)
        image_id = cls.get_image_id(instance_name, region, boto_config)
        if image_id is None:
            cls.LOGGER.critical("ImageId not specified for {} in {}".format(instance_name, region))
            raise Exception("ImageId not specified for {} in {}".format(instance_name, region))
        instance_type = cls.get_instance_type(instance_name, boto_config)

        global_availability_zone =  boto_config.get('availability_zone', None)
        local_availability_zone  = instance_config.get('availability_zone', None)
        availability_zone = local_availability_zone if local_availability_zone else global_availability_zone 

        omit_kargs = boto_config.copy()
        if 'security_groups' in omit_kargs:
            del omit_kargs['security_groups']
        if 'instance_type' in omit_kargs:
            del omit_kargs['instance_type']

        if "availability_zone" in omit_kargs:
            del omit_kargs["availability_zone"]

        
        instance_infos = cls.create_instances(key_name, max_count, image_id, instance_type, security_groups, 
                         instance_tag_specifigations, availability_zone, region=region, **omit_kargs)
        
        if instance_infos is None:
            raise Exception("Failed to create instance: {}".format(instance_name))
        # create volumes in same zone
        instance_ids = list(instance_infos.keys())
        instance_statuses = cls.wait_for_instances(instance_ids)
        volume_names = instance_config.get('volumes', [])
        volume_results = {}
        if len(volume_names) > 0:
            # create the volume
            cls.LOGGER.info("Attaching {} volumes for '{}' in {}".format(len(volume_names), instance_name, region))
            volume_results = cls.attach_instances_to_volumes(instance_name, instance_statuses, volume_names, boto_config)
        return instance_infos, volume_results

    @classmethod
    def attach_instances_to_volumes(cls, instance_name, instance_statuses, volume_names, boto_config):
        availability_zones = cls.get_instances_zone(instance_ids=list(instance_statuses.keys()), **boto_config)
        volume_configs = cls.get_volume_descriptions(boto_config)
        device_configs = {k['volume']: k for k in cls.get_volume_device_descriptions(instance_name, volume_names, boto_config)}
        volume_results = {}
        for name in volume_names:
            volume_config = volume_configs.get(name, None)
            device_config = device_configs.get(name, {})
            volume_results[name] = {}
            if volume_config is None or len(volume_config) == 0 or \
               device_config is None or len(device_config) == 0:
                raise Exception("Attempting to create a volume ({}) for {}, but the device or volume configs are missing",format(name, instance_name)) 
            
            device_name = device_config['device']
            size = volume_config.get('size', None)
            availability_zone = volume_config.get('availability_zone', None)
            snapshotid = volume_config.get('snapshotid', None)
            volumetype = volume_config.get('volumetype', 'standard')
            multiattach = volume_config.get('multiattachenabled', False)
            encrypted = volume_config.get('encrypted', False)
            tags = volume_config.get('tag_specs', [])
            tag_specifications = cls.get_tag_specs_configs(boto_config, tag_specs_names=tags, resource_type='volume')
            size = volume_config.get('size', 100)
            vids = []
            for instance_id, instance_info in instance_statuses.items():
                availability_zone = availability_zones[instance_id]
                cls.LOGGER.debug("Creating volume {} ({}:{}G) for '{}:{}' in {}".format(name, volumetype, size, instance_name,instance_name,  availability_zone))
                vid = cls.create_volume(availability_zone=availability_zone, snapshotid=snapshotid, 
                                  volumetype=volumetype,  multiattach=multiattach,  encrypted=encrypted,
                                  tags=tag_specifications,  size=size, **boto_config)
                
                volume_results[name][instance_id] = {'volume_id': vid,
                                                     'volume_name': name,
                                                     'instance_name': instance_name,
                                                     'device': device_name,
                                                     'attached': False,
                                                     'response': None}
                # use this to capture arguments and attach each volume once they
                # are all available
                vids.append([vid, (instance_id, vid, device_name)])
            
            # wait for all the volumes to be available before attaching them
            _ = cls.wait_for_volumes([i[0] for i in vids], **boto_config)
            for vid, args in vids:
                if vid:
                    rsp = cls.attach_volume(*args, **boto_config)
                    volume_results[name][instance_id]['response'] = rsp
                    volume_results[name][instance_id]['attached'] = True
        return volume_results


    @classmethod
    def get_availability_zones(cls, **kargs):
        ec2 = cls.get_ec2(**kargs)
        zones = ec2.describe_availability_zones()['AvailabilityZones']
        az = [z['ZoneName'] for z in zones if z['State'].lower() == 'available']
        return az

    @classmethod
    def attach_volume(cls, instance_id, volume_id, device_name, **kargs):
        ec2 = cls.get_ec2(**kargs)
        cls.LOGGER.info("Attaching volume ({}) to '{}' as {}".format(instance_id, volume_id, device_name))
        rsp = ec2.attach_volume(InstanceId=instance_id, VolumeId=volume_id, Device=device_name)
        return rsp

    @classmethod
    def get_volumes(cls, volume_ids=None, volume_id=None, **kargs):
        volume_ids = volume_ids if volume_ids is not None else []
        if volume_id is not None:
            volume_ids.append(volume_id)

        ec2 = cls.get_ec2(**kargs)
        volumes = []
        if len(volume_ids) == 0:
            rsp = ec2.describe_volumes()
            volumes = rsp["Volumes"]
        else:
            rsp = ec2.describe_volumes(VolumeIds=volume_ids)
            volumes = rsp["Volumes"]
        if len(volumes) > 0:
            return {k["VolumeId"]: k for k in volumes}
        return {}

    @classmethod
    def find_attached_volumes(cls, volume_id=None, volume_ids=None, ignore_device_names=['/dev/sda1'], **kargs):
        volume_infos = cls.get_volumes(volume_id=volume_id, volume_ids=volume_ids)
        attached = {}
        if ignore_device_names is None:
            ignore_device_names = []
        for vid, info in volume_infos.items():
            if 'Attachments' in info and len(info['Attachments']) > 0:
                valid = True
                for attachment in info['Attachments']:
                    dev_name = attachment.get('Device', None)
                    if dev_name is not None and dev_name in ignore_device_names:
                        valid = False
                        break
                if valid:
                    attached[vid] = info
        return attached

    @classmethod
    def detach_volumes(cls, volume_id=None, volume_ids=None, volume_target_tags=None, ignore_device_names=['/dev/sda1'], **kargs):
        volume_infos = cls.find_attached_volumes(volume_id=volume_id, volume_ids=volume_ids, ignore_device_names=ignore_device_names)
        if isinstance(volume_target_tags, dict):
            volume_infos = cls.find_relevant_volumes(volume_infos=volume_infos, 
                                                     target_tags=volume_target_tags, **kargs)
        ec2 = cls.get_ec2(**kargs)
        cls.LOGGER.info("Detaching {} volumes".format(len(volume_infos)))
        detached_volumes = []
        for vid in volume_infos:
            try:
                cls.LOGGER.debug("Detaching {}".format(vid))
                ec2.detach_volume(VolumeId=vid)
                detached_volumes.append(vid)
            except:
                cls.LOGGER.error("Failed to detach {}:\n{}".format(vid, traceback.format_exc()))

        cls.LOGGER.info("Waiting for {} detached volumes".format(len(detached_volumes)))
        cls.wait_for_volumes(volume_ids=detached_volumes)
        return volume_infos

    @classmethod
    def create_volume(cls, availability_zone=None, snapshotid=None, volumetype="gp2", multiattach=False,
                      encrypted=False, tags=None, size=None, **kargs):
        ec2 = cls.get_ec2(**kargs)

        if availability_zone is None:
            # grab the first one
            az = cls.get_availability_zones(ec2=ec2)
            if len(az) == 0:
                raise Exception("Unable to get an AvailabilityZone")
            availability_zone = az[0]
        _kargs = {"AvailabilityZone": availability_zone,
                  "VolumeType": volumetype, "MultiAttachEnabled": multiattach,
                  "Encrypted": encrypted}
        if tags:
            _kargs["TagSpecifications"] = tags
        if snapshotid:
            _kargs["SnapshotId"] = snapshotid
        if size:
            _kargs["Size"] = size
        # print(_kargs)
        if snapshotid:
            cls.LOGGER.info("Creating volume ({}:{}) using {} in {}".format(volumetype, size, snapshotid, availability_zone, ))
        else:    
            cls.LOGGER.info("Creating volume ({}:{}) in {} for".format(volumetype, size, availability_zone))

        rsp = ec2.create_volume(**_kargs)
        # print(rsp)
        if 'VolumeId' in rsp:
            return rsp['VolumeId']
        return None

    @classmethod
    def check_for_instances_up(cls, instances, **kargs):
        ec2 = cls.get_ec2(**kargs)
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

            instances_completed_loading.append(instance_id)
        return instances_completed_loading

    @classmethod
    def extract_public_ips(cls, instance_infos):
        instance_to_ip = {k['InstanceId']: k.get('PublicIpAddress', '') for k in instance_infos}
        return instance_to_ip

    @classmethod
    def get_instances_zone(cls, instance_ids=None, **kargs):
        instance_infos = cls.get_instance_infos(instance_ids=instance_ids, **kargs)
        ii_az = {}
        for x in instance_infos:
            az = x['Placement']['AvailabilityZone']
            ii_az[x['InstanceId']] = az
        return ii_az

    @classmethod
    def get_instance_infos_zone(cls, instance_infos=None, **kargs):
        if instance_infos is None:
            instance_infos = cls.get_instance_infos(**kargs)
        ii_az = {}
        for x in instance_infos:
            az = x['Placement']['AvailabilityZone']
            ii_az[x['InstanceId']] = az
        return ii_az

    @classmethod
    def get_instance_infos(cls, instance_ids=None, **kargs):
        instance_infos = []
        ec2 = cls.get_ec2(**kargs)
        results = None
        if instance_ids is None or len(instance_ids) == 0:
            results = ec2.describe_instances()
        else:
            results = ec2.describe_instances(InstanceIds=instance_ids)

        if results is None:
            return None
        for k in results['Reservations']:
            instance_infos = instance_infos + k['Instances']        
        return instance_infos

    @classmethod
    def get_instance_public_ips(cls, instance_ids, **kargs):
        instance_infos = cls.get_instance_infos(instance_ids, **kargs)
        return cls.extract_public_ips(instance_infos)

    @classmethod
    def find_relevant_instances(cls, target_tags: dict=None, **kargs):
        target_tags = target_tags if target_tags else {}
        relevant_instances = {}
        instance_infos = cls.get_instance_infos()
        for instance in instance_infos:
            tags = instance.get('Tags', None)
            instance_id = instance['InstanceId']
            public_ip = instance.get('PublicIpAddress', '')
            if tags is None:
                continue

            d_tags = {tag.get('Key', ''):tag.get('Value', '') for tag in tags }
            matching = {k:v for k, v in target_tags.items() if k in d_tags and v == d_tags[k]}
            if len(matching) == len(target_tags):
                matching['public_ip'] = public_ip
                relevant_instances[instance_id] = matching
        return relevant_instances

    @classmethod
    def find_relevant_volumes(cls, target_tags: dict=None, volume_infos=None, **kargs):
        target_tags = target_tags if target_tags else {}
        relevant_volumes = {}
        volume_infos = cls.get_volumes() if volume_infos is None else volume_infos
        for vid, vinfo in volume_infos.items():
            tags = vinfo.get('Tags', None)
            volume_id = vinfo['VolumeId']
            if tags is None:
                continue
            d_tags = {tag.get('Key', ''):tag.get('Value', '') for tag in tags }
            matching = {k:v for k, v in target_tags.items() if k in d_tags and v == d_tags[k]}
            if len(matching) == len(target_tags):
                relevant_volumes[volume_id] = matching
        return relevant_volumes

    @classmethod
    def get_instances(cls, instance_id=None, instance_ids=None, target_tags=None, **kargs):
        ec2 = cls.get_ec2(**kargs)
        if instance_ids is None:
            instance_ids = []

        if instance_id is not None and instance_id not in instance_ids:
            instance_ids.append(instance_id)

        instances = {}
        instance_infos = cls.get_instance_infos(instance_ids=instance_ids, **kargs)
        instances = {k['InstanceId']: k for k in instance_infos }
        if target_tags:
            if not 'ec2' in kargs:
                kargs['ec2'] = ec2
            x = cls.find_relevant_instances(target_tags=target_tags, **kargs)
            if len(x) > 0:
                r = ec2.describe_instances(InstanceIds=[i for i in x])
                instance_infos = []
                for k in r['Reservations']:
                    instance_infos = instance_infos + k['Instances']
                instances.update({k['InstanceId']: k for k in instance_infos })
        return instances



    @classmethod
    def find_relevant_instances_multiple_regions(cls, target_tags: dict=None, regions=REGIONS, **kargs):
        target_tags = target_tags if target_tags else {}
        relevant_instances = []
        for region in regions:
            kargs['region'] = region
            cls.set_region(region)
            instances = cls.find_relevant_instances(target_tags=target_tags, **kargs)
            relevant_instances.append({'region': region, 'instances': instances})
        return relevant_instances

    @classmethod
    def find_relevant_volumes_multiple_regions(cls, target_tags: dict=None, regions=REGIONS, **kargs):
        target_tags = target_tags if target_tags else {}
        relevant_instances = []
        for region in regions:
            kargs['region'] = region
            cls.set_region(region)
            volumes = cls.find_relevant_volumes(target_tags=target_tags, **kargs)
            relevant_instances.append({'region': region, 'volumes': volumes})
        return relevant_instances

    @classmethod
    def terminate_relevant_instances(cls, instance_ids=None, instance_id=None, target_tags: dict=None, dry_run=True, **kargs):
        if instance_ids is None:
            instance_ids = []

        if instance_id not in instance_ids:
            instance_ids.append(instance_id)

        if len(instance_ids) == 0 and (target_tags is None or len(target_tags) == 0):
            cls.LOGGER.critical("WARNING: Must provide tags to filter out instances, or this will destroy the environment")
            raise Exception("Must provide tags to filter out instances, or this will destroy the environment")


        instances = cls.get_instances(instance_ids=instance_id, target_tags=target_tags, **kargs)
        if len(instances) == 0 and len(instance_ids) == 0:
            return instances

        ec2 = cls.get_ec2(**kargs)
        instance_ids = [i for i in instances]
        try:
            cls.LOGGER.debug("Attempting to terminate {} instances.".format(len(instance_ids)))
            ec2.terminate_instances(DryRun=dry_run, InstanceIds=instance_ids)
            cls.LOGGER.info("Terminated {} instances.".format(len(instance_ids)))
        except KeyboardInterrupt:
            cls.LOGGER.error("Failed to terminate {} instances.".format(len(instance_ids)))
        except:
            cls.LOGGER.error("{}".format(traceback.format_exc()))

        return instances

    @classmethod
    def delete_relevant_volumes(cls, target_tags: dict=None, dry_run=True, **kargs):
        if target_tags is None or len(target_tags) == 0:
            cls.LOGGER.critical("WARNING: Must provide tags to filter out instances, or this will destroy the environment")
            raise Exception("Must provide tags to filter out instances, or this will destroy the environment")

        # detach target volumes
        detached_volumes = cls.detach_volumes(target_tags=target_tags, **kargs)
        volumes = cls.find_relevant_volumes(target_tags=target_tags, **kargs)
        if len(volumes) == 0:
            cls.LOGGER.info("No volumes found.")
            return volumes

        ec2 = cls.get_ec2(**kargs)
        for vid in volumes:
            try:
                cls.LOGGER.debug("Attempting to delete volume: {}.".format(vid))
                ec2.delete_volume(DryRun=dry_run, VolumeId=vid)
                cls.LOGGER.info("Deleted volume: {}.".format(vid))
            except KeyboardInterrupt:
                break
            except:
                cls.LOGGER.error("Failed to delete volume: {}.".format(vid))
                cls.LOGGER.error("{}".format(traceback.format_exc()))

        return volumes, detached_volumes

    @classmethod
    def terminate_relevant_instances_multiple_regions(cls, regions=REGIONS, dry_run=True, **kargs):
        relevant_instances = []
        for region in regions:
            cls.set_region(region)
            kargs['region'] = region
            results = cls.terminate_relevant_instances(dry_run=dry_run, **kargs)
            relevant_instances.append({'region': region, 'instances': results})
        return relevant_instances

    @classmethod
    def delete_relevant_volumes_multiple_regions(cls, regions=REGIONS, dry_run=True, **kargs):
        relevant_volumes = []
        for region in regions:
            cls.set_region(region)
            kargs['region'] = region
            results = cls.delete_relevant_volumes(dry_run=dry_run, **kargs)
            relevant_volumes.append({'region': region, 'volumes': results})
        return relevant_volumes

    @classmethod
    def stop_relevant_instances(cls, instance_ids=None, instance_id=None, target_tags: dict=None, dry_run=True, **kargs):
        if instance_ids is None:
            instance_ids = []

        if instance_id not in instance_ids:
            instance_ids.append(instance_id)

        if len(instance_ids) == 0 and (target_tags is None or len(target_tags) == 0):
            cls.LOGGER.critical("WARNING: Must provide tags to filter out instances, or this will destroy the environment")
            raise Exception("Must provide tags to filter out instances, or this will destroy the environment")


        instances = cls.get_instances(instance_ids=instance_id, target_tags=target_tags, **kargs)
        if len(instances) == 0 and len(instance_ids) == 0:
            return instances

        ec2 = cls.get_ec2(**kargs)
        instance_ids = [i for i in instances]
        try:
            cls.LOGGER.debug("Attempting to stop {} instances: {}.".format(len(instance_ids)))
            ec2.stop_instances(DryRun=dry_run, InstanceIds=instance_ids)
            cls.LOGGER.info("Stopped instace: {}.".format(vid))
        except KeyboardInterrupt:
            cls.LOGGER.error("Failed to stop {} instances.".format(len(instance_ids)))
        except:
            cls.LOGGER.error("{}".format(traceback.format_exc()))

        return instances

    @classmethod
    def reboot_relevant_instances(cls, instance_ids=None, instance_id=None, target_tags: dict=None, dry_run=True, **kargs):
        if instance_ids is None:
            instance_ids = []

        if instance_id not in instance_ids:
            instance_ids.append(instance_id)

        if len(instance_ids) == 0 and (target_tags is None or len(target_tags) == 0):
            cls.LOGGER.critical("WARNING: Must provide tags to filter out instances, or this will destroy the environment")
            raise Exception("Must provide tags to filter out instances, or this will destroy the environment")


        instances = cls.get_instances(instance_ids=instance_id, target_tags=target_tags, **kargs)
        if len(instances) == 0 and len(instance_ids) == 0:
            return instances

        ec2 = cls.get_ec2(**kargs)
        instance_ids = [i for i in instances]
        try:
            cls.LOGGER.debug("Attempting to reboot {} instances: {}.".format(len(instance_ids)))
            ec2.reboot_instances(DryRun=dry_run, InstanceIds=instance_ids)
            cls.LOGGER.info("Rebooted instace: {}.".format(vid))
        except KeyboardInterrupt:
            cls.LOGGER.error("Failed to reboot {} instances.".format(len(instance_ids)))
        except:
            cls.LOGGER.error("{}".format(traceback.format_exc()))

        return instances

    @classmethod
    def start_relevant_instances(cls, instance_ids=None, instance_id=None, target_tags: dict=None, dry_run=True, **kargs):
        if instance_ids is None:
            instance_ids = []

        if instance_id not in instance_ids:
            instance_ids.append(instance_id)

        if len(instance_ids) == 0 and (target_tags is None or len(target_tags) == 0):
            cls.LOGGER.critical("WARNING: Must provide tags to filter out instances, or this will destroy the environment")
            raise Exception("Must provide tags to filter out instances, or this will destroy the environment")


        instances = cls.get_instances(instance_ids=instance_id, target_tags=target_tags, **kargs)
        if len(instances) == 0 and len(instance_ids) == 0:
            return instances

        ec2 = cls.get_ec2(**kargs)
        instance_ids = [i for i in instances]
        try:
            cls.LOGGER.debug("Attempting to start {} instances: {}.".format(len(instance_ids)))
            ec2.start_instances(DryRun=dry_run, InstanceIds=instance_ids)
            cls.LOGGER.info("Started instace: {}.".format(vid))
        except KeyboardInterrupt:
            cls.LOGGER.error("Failed to start {} instances.".format(len(instance_ids)))
        except:
            cls.LOGGER.error("{}".format(traceback.format_exc()))

        return instances