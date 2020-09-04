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

from mongoengine import *


class RegisteredSensor(Document):
    sensor_id = StringField(required=True)
    sensor_ip = StringField(required=True)
    token = StringField(required=True)
    created_at = StringField(required=True)
    received_at = StringField(required=True)
    last_ping = StringField(required=True)

class TokenInfo(Document):
    creator_token = StringField(required=True)
    token = StringField(required=True)
    email = StringField(required=True)
    name = StringField(required=True)
    description = StringField(required=True)
    is_admin = BooleanField(required=True)
    is_active = BooleanField(required=True)
    created_at = StringField(required=True)
    modified_at = StringField(required=True)
    last_used = StringField(required=True)


class PingSensor(Document):
    sensor_id = StringField(required=True)
    sensor_ip = StringField(required=True)
    token = StringField(required=True)
    created_at = StringField(required=True)
    received_at = StringField(required=True)


class GeneralEvent(Document):
    sensor_id = StringField(required=True)
    sensor_ip = StringField(required=True)
    src_ip = StringField(required=True)
    src_port = IntField(required=True)
    dst_ip = StringField(required=True)
    dst_port = IntField(required=True)
    created_at = StringField(required=True)
    rtype = StringField(required=True)
    response = StringField(required=True)
    request = StringField(required=True)
    request_data = DictField()
    api = StringField(required=True)
    sent = BooleanField(required=True)
    event_id = StringField(required=True)

class RequestResultEvent(Document):
    sensor_id = StringField(required=True)
    sensor_ip = StringField(required=True)
    created_at = StringField(required=True)
    received_at = StringField(required=True)
    response_info = DictField()
    request_parameters = DictField()
    result_id = StringField(required=True)

class CreateEvent(Document):
    src_ip = StringField(required=True)
    src_port = IntField(required=True)
    dst_ip = StringField(required=True)
    dst_port = IntField(required=True)
    created_at = StringField(required=True)
    command = StringField(required=True)
    image = StringField(required=True)
    event_id = StringField(required=True)
