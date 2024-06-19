"""
Copyright 2021 Intrinsec

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
from __future__ import absolute_import, print_function

import sys
import json
import ssl
import os
import uuid
import logging
import logging.handlers
from collections import OrderedDict
from urllib.parse import urlparse
from urllib.request import ProxyHandler, Request, build_opener, urlopen
from future.standard_library import install_aliases

install_aliases()

APP_NAME = "TA-tg_api_alert"
HTTP_REQUEST_TIMEOUT = 60
SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")


def get_header(session_key, header_name, logger):
    from splunk.entity import getEntities

    try:
        entities = getEntities(
            ["admin", "passwords"],
            namespace=APP_NAME,
            owner="nobody",
            sessionKey=session_key,
            count=-1,
        )
    except Exception as e:
        logger.error("Could not get stored headers from splunk. Error: {}".format(e))
        raise Exception(
            "Could not get %s stored headers from splunk. Error: %s"
            % (APP_NAME, str(e))
        )

    realm_headers = [h for _, h in entities.items() if h["realm"] == APP_NAME]

    header = next(
        (h for h in realm_headers if h["username"] == header_name),
        None,
    )
    if header is not None:
        return header["clear_password"]

    error = "No header {} has been found in realm {}, here are the available headers: {}".format(
        header_name, APP_NAME, ",".join(realm_headers)
    )
    logger.critical(error)
    raise Exception(error)


def encode(string, encodings=None):
    PY2 = sys.version_info[0] == 2

    if not PY2 and isinstance(string, bytes):
        return string

    if PY2 and isinstance(string, str):
        return string

    encodings = encodings or ["utf-8", "latin1", "ascii"]

    for encoding in encodings:
        try:
            return string.encode(encoding)
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass

    return string.encode(encodings[0], errors="ignore")


def send_http_request(url, encoded_data, headers, logger, proxy=None):
    if not validate_url(url):
        logger.critical("Configured URL {} is not a valid https URL".format(url))
        return

    req = Request(url, encoded_data, headers)
    opener = urlopen
    if proxy:
        if not validate_proxy(proxy):
            logger.critical("Configured URL {} is not a valid https URL".format(url))
            return
        handler = ProxyHandler({"https": proxy})
        opener = build_opener(handler).open

    try:
        response = opener(req, timeout=HTTP_REQUEST_TIMEOUT)  # nosec
        logger.info("Received response HTTP status {}".format(response.code))

        if 200 <= response.code < 300:
            logger.info("HTTP request successfully sent")
        elif response.code in [401, 403]:
            logger.critical("Missing or invalid authentication token")
        else:
            logger.error("Failed to send HTTP request: {}".format(response.msg))
    except Exception as e:
        logger.error("Error sending HTTP request to {}, got error {}".format(url, e))


def validate_url(url):
    validate_url = urlparse(url)
    if not all(
        [
            validate_url.scheme == "https",
            validate_url.netloc,
            validate_url.path,
        ]
    ):
        return False
    return True


def validate_proxy(url):
    validate_url = urlparse(url)
    if validate_url.scheme not in ["http", "https"]:
        return False
    return True


def setup_logging(uuid):
    logger = logging.getLogger("splunk.TA-tg_api_alert")

    LOGGING_DEFAULT_CONFIG_FILE = os.path.join(SPLUNK_HOME, "etc", "log.cfg")
    LOGGING_LOCAL_CONFIG_FILE = os.path.join(SPLUNK_HOME, "etc", "log-local.cfg")
    LOGGING_STANZA_NAME = "python"
    LOGGING_FILE_NAME = "TA-tg_api_alert.log"
    BASE_LOG_PATH = os.path.join("var", "log", "splunk")
    LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t%(module)s:%(lineno)d - {}: %(message)s".format(  # noqa
        uuid
    )
    splunk_log_handler = logging.handlers.RotatingFileHandler(
        os.path.join(SPLUNK_HOME, BASE_LOG_PATH, LOGGING_FILE_NAME), mode="a"
    )
    splunk_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
    from splunk import setupSplunkLogger

    setupSplunkLogger(
        logger,
        LOGGING_DEFAULT_CONFIG_FILE,
        LOGGING_LOCAL_CONFIG_FILE,
        LOGGING_STANZA_NAME,
    )
    return logger


def send_event(url, api_token, body, logger, proxy=None):
    logger.info('Sending event to url="%s" with body="%s"' % (url, body))
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_token
    }
    send_http_request(url, body, headers, logger, proxy)


def main():
    alert_uuid = str(uuid.uuid4())
    logger = setup_logging(alert_uuid)

    if len(sys.argv) <= 1 or sys.argv[1] != "--execute":
        logger.critical("Unsupported execution mode (expected --execute flag)")
        sys.exit(1)

    payload = json.loads(sys.stdin.read())

    settings = payload['configuration']
    url = settings.get('url')
    proxy = settings.get('proxy')
    header_name = settings.get('header')
    session_key = payload.get('session_key')

    try:
        api_token = get_header(session_key, header_name, logger)
    except Exception as e:
        logger.critical("Failed to retrieve API token: {}".format(e))
        sys.exit(1)

    body = OrderedDict(
        sid=payload.get('sid'),
        search_name=payload.get('search_name'),
        app=payload.get('app'),
        owner=payload.get('owner'),
        results_link=payload.get('results_link'),
        result=payload.get('result')
    )

    encoded_body = json.dumps(body).encode()

    send_event(url, api_token, encoded_body, logger, proxy)


if __name__ == "__main__":
    main()
