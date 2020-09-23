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

from quart import Quart, jsonify, Response, request
import os
import tempfile
import ssl
import traceback
import asyncio
from hypercorn.config import Config as HyperConfig
from hypercorn.asyncio import serve
from .consts import *
from .util import *
import logging

class Hypercorn(Quart):
    APP_TEMP_DIR = tempfile.TemporaryDirectory()
    CERTS_PATH = os.path.join(APP_TEMP_DIR.name, 'ssl')
    LOGGER = get_stream_logger(__name__ + '.Hypercorn')
    APP_TEMP_DIR = tempfile.TemporaryDirectory()
    CERTS_PATH = os.path.join(APP_TEMP_DIR.name, 'ssl')
    DEFAULT_PORT = 8000

    def __init__(self, name, host='0.0.0.0', port=DEFAULT_PORT, 
                 ca_crt=None, server_crt=None, server_key=None,
                 certs_path=CERTS_PATH, debug=False):
        super().__init__(name)
        self._App_host = host
        self._App_port = port

        self._App_server_ca = None
        self._App_server_key = None
        self._App_server_crt = None


        if ca_crt is not None and \
           server_crt is not None and \
           server_key is not None:
            self._App_server_ca = os.path.join(certs_path if certs_path else '', ca_crt)
            self._App_server_key = os.path.join(certs_path if certs_path else '', server_key)
            self._App_server_crt = os.path.join(certs_path if certs_path else '', server_crt)

            self._App_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            self._App_context.load_verify_locations(self._App_server_ca)
            self._App_context.load_cert_chain(self._App_server_crt, self._App_server_key)
        else:
            self._App_context = None

    def add_route(rule, endpoint, view_func, provide_automatic_options=None, **options):
        self.add_url_rule(rule, endpoint, view_func, provide_automatic_options, **options)

    def do_run(self):
        try:
            self.run(self._App_host, self._App_port, ssl_context=self._App_context)
        except:
            self.LOGGER.error('Unable to start server on {}:{}'.format(self._App_host, self._App_port))
            self.LOGGER.error('{}'.format(traceback.format_exc()))
            raise

    def quart_run(self):
        # looked at the hypercorn and quart Python project to figure out
        # how to start the application separately, without going through
        # the Quart.app.run APIs
        config = HyperConfig()
        config.debug = self.debug
        config.access_log_format = "%(h)s %(r)s %(s)s %(b)s %(D)s"
        config.accesslog = self.LOGGER
        config.bind = ["{host}:{port}".format(**{'host':self._App_host,
                                                 'port':self._App_port})]
        config.certfile = self._App_server_crt
        config.keyfile = self._App_server_key

        config.errorlog = config.accesslog
        config.use_reloader = True
        scheme = "https" if config.ssl_enabled else "http"

        self.LOGGER.info("Running on {}://{} (CTRL + C to quit)".format(scheme, config.bind[0]))
        loop = None #asyncio.get_event_loop()
        if loop is not None:
            loop.set_debug(debug or False)
            loop.run_until_complete(serve(self, config))
        else:
            asyncio.run(serve(self, config), debug=config.debug)

