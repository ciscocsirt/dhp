from .util import *
from .notify import get_single_notifier, notifier_initted
from .consts import *
from .notify import *
from .simple_commands.app import Hypercorn as App
from time import sleep
import asyncio
import argparse
from multiprocessing import Process
from quart import Quart, jsonify, Response, request, url_for, make_response
import jinja2
from jinja2 import Environment, BaseLoader
import json
from .commands import *
from .simple_commands.util import *

BASIC_WEB_REQUEST_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Remote Web Request</title>
</head>
<body>
    <form autocomplete="on" action="{{ url_location }}" method="post" id="web_request" name="web_request">
        <label for="token"> Token:</label>
        <input type="text" id="token" name="token"><br>
        <label for="sensor_id"> Sensor IP:</label>
        <input type="text" id="sensor_ip" name="sensor_ip"><br>
        <label for="sensor_id"> Sensor ID:</label>
        <input type="text" id="sensor_id" name="sensor_id"><br>
        <label for="url"> URL:</label>
        <input type="text" id="url" name="url"><br>
        <label for="user_agent"> User-Agent:</label>
        <input type="text" id="user_agent" name="user_agent"><br>
        <label for="json_payload"> JSON Payload (as JSON Dictionary):</label><br>
        <textarea id="json_payload" name="json_payload" rows="10" cols="80"></textarea><br>
        <label for="data_payload"> Data Payload (as JSON Dictionary):</label><br>
        <textarea id="data_payload" name="data_payload" rows="10" cols="80"></textarea><br>
        <label for="parameters"> URI Parameters (as JSON Dictionary):</label><br>
        <textarea id="parameters" name="parameters" rows="10" cols="80"></textarea><br>
        <label for="headers"> HTTP Client Headers (as JSON Dictionary):</label><br>
        <textarea id="headers" name="headers" rows="10" cols="80"></textarea><br>
        <button type="submit">Submit</button>
    </form>
</body>
</html>
'''

CA_LOGGER = get_stream_logger(__name__)
BASIC_WEB_REQUEST_TEMPLATE = Environment(loader=BaseLoader).from_string(BASIC_WEB_REQUEST_PAGE)

async def handle_remote_web_request_page():
    method = request.method
    await request.data
    await request.data
    if method == 'GET':
        return Response(BASIC_WEB_REQUEST_TEMPLATE.render(url_location=url_for("basic_submit_web_request")), 200)
    elif method == 'POST':
        form = await request.form
        # clean up inputs
        data = dict(form.items())
        data[DATA_PAYLOAD] = dict_or_none(form.get(DATA_PAYLOAD, None))
        data[HEADERS] = dict_or_none(form.get(HEADERS, None))
        data[PARAMETERS] = dict_or_none(form.get(PARAMETERS, None))
        data[JSON_PAYLOAD] = dict_or_none(form.get(JSON_PAYLOAD, None))
        data[SENSOR_ID] = str_or_none(form.get(SENSOR_ID, None))
        data[SENSOR_IP] = str_or_none(form.get(SENSOR_IP, None))
        data[TOKEN] = str_or_none(form.get(TOKEN, None))
        data[URL] = url_or_none(form.get(URL, None))
        url = data[URL]
        sensor_id = data[SENSOR_ID]
        sensor_ip = data[SENSOR_IP]
        incoming_token = data[TOKEN]
        skargs = {SENSOR_ID:sensor_id, 
              SENSOR_IP: sensor_ip, 
              TOKEN: None}
        
        if incoming_token and notifier_initted() and not await get_single_notifier().is_valid(incoming_token):
            return Response('', status=403)            
        elif incoming_token is None:
            return Response('', status=200)

        sensor_infos = None
        do_sensor_id_custom_ip = sensor_id is not None and sensor_ip is not None
        if notifier_initted():
            if sensor_id is not None:    
                sensor_infos = get_single_notifier().get_sensor_infos(sensor_id=sensor_id)
            else:
                sensor_infos = get_single_notifier().get_sensor_infos()
        
        if len(sensor_infos) == 0:
            return Response('', status=200)

        request_parameters =  CommandHandler.build_perform_web_request_payload(**data)
        base_payload = {k: v for k, v in skargs.items() if not v is None}
        base_payload.update(request_parameters)

        CA_LOGGER.info("Recv'd remote web request for {} ({})".format(sensor_id, sensor_ip))

        all_payloads = base_payload.copy()
        all_payloads[SENSOR_IP] = []
        all_payloads[SENSOR_ID] = []
        all_payloads[TOKEN] = []

        if notifier_initted() and sensor_infos is not None and len(sensor_infos) > 0:
            try:
                # sensor_infos = get_single_notifier().get_sensor_infos(**skargs)
                message = "Failed to submit url to sensors: {}".format(url)
                
                token = get_single_notifier().server_secret_key
                if len(sensor_infos) > 1 and not do_sensor_id_custom_ip:
                    for si in sensor_infos:
                        payload = base_payload.copy()
                        payload[SENSOR_IP] = si.sensor_ip
                        payload[SENSOR_ID] = si.sensor_id
                        payload[TOKEN] = token
                        sensor_id = si.sensor_id
                        sensor_ip = si.sensor_ip
                        all_payloads[SENSOR_IP].append(sensor_ip)
                        all_payloads[SENSOR_ID].append(sensor_id)
                        all_payloads[TOKEN].append(si.token)
                        CA_LOGGER.info("Submitted request to {} {} for url: {}".format(sensor_id, sensor_ip, url))
                        await CommandHandler.submit_remote_web_request_cmd(si.sensor_id, si.sensor_ip, DEFAULT_HP_LPORT, token, payload)

                    message = "Submitted request {} for url: {}".format(len(sensor_infos), url)
                elif len(sensor_infos) == 1 or do_sensor_id_custom_ip:
                    token = get_single_notifier().server_secret_key
                    if sensor_id is not None:
                        si = [i for i in sensor_infos if sensor_id == i.sensor_id][0]
                    else:
                        si = sensor_infos[0]
                    
                    sensor_id = si.sensor_id if sensor_id is None else sensor_id
                    sensor_ip = si.sensor_ip if sensor_ip is None else sensor_ip
                    payload = base_payload.copy()
                    payload[SENSOR_IP] = sensor_ip
                    payload[SENSOR_ID] = sensor_id
                    payload[TOKEN] = token
                    all_payloads[SENSOR_IP].append(sensor_ip)
                    all_payloads[SENSOR_ID].append(sensor_id)
                    all_payloads[TOKEN].append(si.token)
                    CA_LOGGER.info("Submitted request to {} {} for url: {}".format(si.sensor_id, si.sensor_ip, url))
                    await CommandHandler.submit_remote_web_request_cmd(sensor_id, sensor_ip, DEFAULT_HP_LPORT, token, payload)
                    message = "Submitted request to {}({}) for url: {}".format(sensor_id, sensor_ip, url)    
                await request.data
                return Response(str(json.dumps(all_payloads,  indent=4, sort_keys=True)), status=200)
            except:
                all_payloads['message'] = "failed to create request"
                all_payloads['exception'] = traceback.format_exc()
                return Response(str(json.dumps(all_payloads,  indent=4, sort_keys=True)), status=500)
    return Response('', status=200)

async def handle_events():
    events = None
    try:
        payload = json.loads(await request.data)
        events = payload.get(EVENTS, None)
        token = payload.get(TOKEN, None)
        sensor_ip = payload.get(SENSOR_IP, None)
        sensor_id = payload.get(SENSOR_ID, None)
        dt = payload.get(DATETIME, None)
        now = get_iso_time()
        
        if sensor_id is None or sensor_ip is None or token is None:
            return Response('', status=200)
        elif events is None or len(events) == 0:
             return Response('', status=400)

        CA_LOGGER.info("Recv'd {} events from {} ({}), initted: {}".format(len(events), sensor_id, sensor_ip, notifier_initted()))
        if notifier_initted() and not await get_single_notifier().is_valid(token):
            return Response('', status=403)            

        if notifier_initted():
            await get_single_notifier().touch_token(token, now)
            await get_single_notifier().collector_notify(sensor_id, sensor_ip, token, dt, now, events)
            CA_LOGGER.debug("Logged {} events from {} ({})".format(len(events), sensor_id, sensor_ip))
    except:
        return Response('', status=500)
    return Response('', status=200)


async def handle_register():
    events = None
    try:
        payload = json.loads(await request.data)
        events = payload.get(EVENTS, None)
        token = payload.get(TOKEN, None)
        sensor_ip = payload.get(SENSOR_IP, None)
        sensor_id = payload.get(SENSOR_ID, None)
        dt = payload.get(DATETIME, None)
        now = get_iso_time()
        if sensor_id is None or sensor_ip is None or token is None or dt is None:
            return Response('', status=200)

        if notifier_initted() and not await get_single_notifier().is_valid(token):
            return Response('', status=403)            

        CA_LOGGER.info("Recv'd registration from {} ({})".format(sensor_id, sensor_ip))
        if notifier_initted():
            await get_single_notifier().touch_token(token, now)
            await get_single_notifier().register_sensor(sensor_id, sensor_ip, token, dt, now)
    except:
        traceback.print_exc()
        return Response('', status=500)
    return Response('', status=200)


async def create_response_file_data(filename, sensor_result):
    response_info = sensor_result.response_info
    b64data = response_info.get(CONTENT, None)
    if b64data is None:
        data = b''
    else:
        data = base64.b64decode(b64data)

    response = await make_response(data)
    response.headers['Content-Type'] = "application/zip"
    response.headers['Content-Disposition'] = "inline; filename=" + filename
    return response

async def handle_get_event(token, event_id):
    result_id = event_id
    try:
        CA_LOGGER.info("Recv'd get_event request".format())

        if notifier_initted() and await get_single_notifier().is_valid(token):
            result = await get_single_notifier().get_event(result_id)
            data = {}
            data['sensor_id'] = result.sensor_id
            data['sensor_ip'] = result.sensor_ip
            data['src_ip'] = result.src_ip
            data['src_port'] = result.src_port
            data['dst_ip'] = result.dst_ip
            data['dst_port'] = result.dst_port
            data['created_at'] = result.created_at
            data['rtype'] = result.rtype
            data['response'] = result.response
            data['request_data'] = result.request_data
            data['api'] = result.api
            data['sent'] = result.sent
            data['event_id'] = result.event_id
            return jsonify(data)
    except:
        CA_LOGGER.info("Download ID:{}, exception: {}".format(result_id, traceback.format_exc()))
        return Response('', status=500)
    return Response('', status=500)

async def handle_summary_downloads(result_id):
    result_id = result_id
    events = None
    try:
        CA_LOGGER.info("Recv'd download request".format())

        if notifier_initted():
            result = await get_single_notifier().get_request_result(result_id)
            data = {}
            data['sensor_id'] = result.sensor_id
            data['sensor_ip'] = result.sensor_ip
            data['created_at'] = result.created_at
            data['received_at'] = result.received_at
            data['response_info'] = result.response_info
            data['request_parameters'] = result.request_parameters
            data['result_id'] = result.result_id
            return jsonify(data)
    except:
        CA_LOGGER.info("Download ID:{}, exception: {}".format(result_id, traceback.format_exc()))
        return Response('', status=500)
    return Response('', status=500)

async def handle_file_downloads(result_id):
    result_id = result_id
    try:
        CA_LOGGER.info("Recv'd download request".format())

        if notifier_initted():
            result = await get_single_notifier().get_request_result(result_id)
            if result:
                response = await create_response_file_data('content.zip', result)
                return response
            
            raise Exception("result_id did not take, {} ".format(result_id))
    except:
        msg = "Download ID:{}, exception: {}".format(result_id, traceback.format_exc())
        CA_LOGGER.info(msg)
        return Response(msg, status=500)
    return Response('failed to find linke', status=500)


async def handle_new_token():
    events = None
    try:
        payload = json.loads(await request.data)
        token = payload.get(TOKEN, None)
        email = payload.get(EMAIL, None)
        name = payload.get(NAME, None)
        description = payload.get(DESCRIPTION, None)
        is_admin = payload.get(IS_ADMIN, False)
        if token is None or email is None or name is None or description is None:
            return Response('', status=200)

        CA_LOGGER.info("Recv'd registration from {} ({})".format(sensor_id, sensor_ip))

        if notifier_initted() and not get_single_notifier().is_admin(token):
            return Response('', status=403)            

        if notifier_initted():
            await get_single_notifier().touch_token(token, now)
            token_info = await get_single_notifier().new_token(token, email=email, name=name, description=description, is_admin=is_admin)
        return jsonify(token=token_info.token)
    except:
        return Response('', status=500)
    return Response('', status=500)


async def handle_ping():
    events = None
    try:
        payload = json.loads(await request.data)
        events = payload.get(EVENTS, None)
        token = payload.get(TOKEN, None)
        sensor_ip = payload.get(SENSOR_IP, None)
        sensor_id = payload.get(SENSOR_ID, None)
        dt = payload.get(DATETIME, None)
        now = get_iso_time()
        CA_LOGGER.info("Recv'd ping from {} ({})".format(sensor_id, sensor_ip))
        if sensor_id is None or sensor_ip is None or token is None or dt is None:
            return Response('', status=200)

        if notifier_initted() and not await get_single_notifier().is_valid(token):
            return Response('', status=403)            

        if notifier_initted():
            await get_single_notifier().touch_token(token, now)
            await get_single_notifier().ping_sensor(sensor_id, sensor_ip, token, dt, now)
    except:
        traceback.print_exc()
        return Response('', status=500)
    return Response('', status=200)


async def handle_remote_command_responses():
    events = None
    try:
        payload = json.loads(await request.data)
        events = payload.get(EVENTS, None)
        token = payload.get(TOKEN, None)
        sensor_ip = payload.get(SENSOR_IP, None)
        sensor_id = payload.get(SENSOR_ID, None)
        dt = payload.get(DATETIME, None)
        now = get_iso_time()
        
        if sensor_id is None or sensor_ip is None or token is None or dt is None:
            CA_LOGGER.info("Failed to add results remote command results from {} ({})".format(sensor_id, sensor_ip))
            return Response('', status=200)
        CA_LOGGER.info("Recv'd remote command results from {} ({})".format(sensor_id, sensor_ip))
        if get_single_notifier() is None:
            CA_LOGGER.info("No notifer present from {} ({})".format(sensor_id, sensor_ip))
        if notifier_initted() and not await get_single_notifier().is_valid(token):
            return Response('', status=403)            

        if notifier_initted():
            CA_LOGGER.info("Adding response results from {} ({})".format(sensor_id, sensor_ip))
            # print(str(json.dumps(payload,  indent=4, sort_keys=True)))
            # await get_single_notifier().touch_token(token, now)
            try:
                await get_single_notifier().requests_sensor(sensor_id, sensor_ip, token, dt, now, payload)
            except:
                CA_LOGGER.info(traceback.format_exc())
    except:

        return Response('', status=500)
    return Response('', status=200)



