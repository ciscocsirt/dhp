from mongoengine import *


class RegisteredSensor(Document):
    sensor_id = StringField(required=True)
    sensor_ip = StringField(required=True)
    token = StringField(required=True)
    created_at = StringField(required=True)
    received_at = BooleanField(required=True)

class PingSensor(Document):
    sensor_id = StringField(required=True)
    sensor_ip = StringField(required=True)
    token = StringField(required=True)
    created_at = StringField(required=True)
    received_at = BooleanField(required=True)


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

class CreateEvent(Document):
    src_ip = StringField(required=True)
    src_port = IntField(required=True)
    dst_ip = StringField(required=True)
    dst_port = IntField(required=True)
    created_at = StringField(required=True)
    command = StringField(required=True)
    image = StringField(required=True)
