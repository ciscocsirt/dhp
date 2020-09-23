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

HIBERNATEABLE = ["m3",  "m4",  "m5",  "c3",  "c4",  "c5",  "r3",  "r4", "r5"]
STANDARD_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

DEFAULT_PORT = 8000
UBUNTU = 'ubuntu'

COPY_FILE = 'sudo cp {src} {dst}'

INSTALL_SYSTEMCTL_COMMANDS = [
    'sudo cp {service_name}.service /lib/systemd/system/',
    'sudo chmod 644 /lib/systemd/system/{service_name}.service',
    'sudo systemctl daemon-reload',
    'sudo systemctl enable {service_name}.service',
    'sudo systemctl start {service_name}.service',
    'sudo systemctl status {service_name}.service'
]

DOCKER_SETUP_COMMANDS = [
    'sudo apt update && sudo apt install -y apt-transport-https ca-certificates curl software-properties-common git python3-pip',
    'curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -',
    'sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"',
    'sudo apt update && sudo apt install -y docker-ce docker-compose',
    'sudo usermod -aG docker {username}',
]


IPIFY_URL = "https://api.ipify.org/?format=json"

REGION_TO_AMI = {
    'us-east-1':"",
    'us-east-2':"",
    'us-west-1':"",
    'us-west-2':"",
    'sa-east-1':"",
    # 'ap-east-1':"ami-107d3e61",
    'ap-south-1':"",
    'ap-southeast-1':"",
    'ap-southeast-2':"",
    'ap-northeast-1':"",
    'ap-northeast-2':"",

    "eu-north-1": "",
    "eu-central-1": "",
    "eu-west-1": "",
    "eu-west-2": "",
    "eu-west-3": "",

}

DEFAULT_REGION = 'us-east-2'
DCS = list(REGION_TO_AMI.keys())

MATCH_KEYS = [
    'image_architecture',
    'image_owner_alias',
    'image_owner_id',
    'image_virtualization_type',
]