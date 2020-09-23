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
    'us-east-1':"ami-0bcc094591f354be2",
    'us-east-2':"ami-0bbe28eb2173f6167",
    'us-west-1':"ami-0dd005d3eb03f66e8",
    'us-west-2':"ami-0a634ae95e11c6f91",
    'sa-east-1':"ami-08caf314e5abfbef4",
    # 'ap-east-1':"ami-107d3e61",
    'ap-south-1':"ami-02b5fbc2cb28b77b8",
    'ap-southeast-1':"ami-0007cf37783ff7e10",
    'ap-southeast-2':"ami-0f87b0a4eff45d9ce",
    'ap-northeast-1':"ami-01c36f3329957b16a",
    'ap-northeast-2':"ami-05438a9ce08100b25",

    "eu-north-1": "ami-0363142d8c97b94c8",
    "eu-central-1": "ami-04932daa2567651e7",
    "eu-west-1": "ami-07ee42ba0209b6d77",
    "eu-west-2": "ami-04edc9c2bfcf9a772",
    "eu-west-3": "ami-03d4fca0a9ced3d1f",

}

DEFAULT_REGION = 'us-east-2'
DEFAULT_IMAGE_ID = REGION_TO_AMI[DEFAULT_REGION]
DCS = list(REGION_TO_AMI.keys())
