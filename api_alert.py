Steps to Integrate and Deploy the Script in Splunk
1.	Prepare the Directory Structure: Ensure your Splunk app directory TA-tg_api_alert has the following structure:
sql
Copy code
TA-tg_api_alert/
├── bin/
│   └── api_alert.py
├── default/
│   ├── savedsearches.conf
│   └── app.conf
├── README/
├── metadata/
└── local/
    └── savedsearches.conf
2.	Place the Script in the bin/ Directory: Save the updated script as api_alert.py in the bin/ directory of your Splunk app.
3.	Update savedsearches.conf: Configure your saved searches to call this script. Here's an example of how you might configure a saved search in savedsearches.conf:
ini
Copy code
[my_scheduled_search]
action.script = 1
action.script.filename = api_alert.py
action.script.arg1 = --execute
action.script.arg2 = "{api_token}"
action.script.arg3 = "{env}"
alert.digest_mode = True
alert.suppress = False
cron_schedule = */5 * * * *
description = My scheduled search for testing TA-tg_api_alert
search = index=_internal sourcetype=splunkd_access
4.	Configure app.conf: Ensure app.conf is correctly configured. Here is a basic setup for app.conf:
ini
Copy code
[id]
name = TA-tg_api_alert
version = 1.0.0
build = 1
 
[launcher]
author = Your Name
description = App to send alerts to TemperedGlass API
version = 1.0.0
visible = true
 
[ui]
is_visible = 1
 
[install]
is_configured = 1
5.	Package the App: Create a tar.gz file of your app directory to install it on the Splunk server.
sh
Copy code
tar -czvf TA-tg_api_alert.tar.gz TA-tg_api_alert/
6.	Install the App on Your Splunk Instance: Upload the tar.gz file to your Splunk instance via the "Manage Apps" interface.
7.	Restart Splunk: After installing the app, restart Splunk to ensure the app and configurations are loaded correctly.
8.	Test the Alert: Create a new alert in Splunk that uses your saved search and triggers the script. Monitor the logs and outputs to ensure everything is working as expected.
Updated Script with Secure Token Input
Here's the updated script, ensuring the user input for the API token is hidden and can be verified:
python
Copy code
import json
import logging
import logging.handlers
import os
import sys
import uuid
import getpass
from urllib.parse import urlparse
from urllib.request import ProxyHandler, Request, build_opener, urlopen
 
APP_NAME = "TA-tg_api_alert"
HTTP_REQUEST_TIMEOUT = 60
SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
 
# Hard-coded webhook URLs
WEBHOOK_URLS = {
    "prod": "https://4b9jdy88w1.execute-api.us-east-1.amazonaws.com/api/alert",
    "stage": "https://ghptuijhz1.execute-api.us-east-1.amazonaws.com/api/alert"
}
 
def validate_url(url):
    """Check that URL is valid
    Check that the URL is in HTTPS
    and that it has a netloc and a path
    """
    parsed_url = urlparse(url)
    return all([parsed_url.scheme == "https", parsed_url.netloc, parsed_url.path])
 
def encode(string, encodings=None):
    if isinstance(string, str):
        return string.encode('utf-8')
    return string
 
def send_http_request(url, encoded_data, headers, logger, proxy=None):
    if not validate_url(url):
        logger.critical("Configured URL {} is not a valid https URL".format(url))
        return
 
    req = Request(url, encoded_data, headers)
    opener = urlopen
    if proxy:
        if not validate_proxy(proxy):
            logger.critical("Configured proxy {} is not a valid URL".format(proxy))
            return
        handler = ProxyHandler({"https": proxy})
        opener = build_opener(handler).open
 
    try:
        response = opener(req, timeout=HTTP_REQUEST_TIMEOUT)
        logger.info("Received response HTTP status {}".format(response.code))
        if 200 <= response.code < 300:
            logger.info("HTTP request successfully sent")
        elif response.code in [401, 403]:
            logger.critical("Missing or invalid authentication token")
        else:
            logger.error("Failed to send HTTP request: {}".format(response.msg))
    except Exception as e:
        logger.error("Error sending HTTP request to {}, got error {}".format(url, e))
 
def setup_logging(uuid):
    logger = logging.getLogger("splunk.api_alerts")
    LOGGING_DEFAULT_CONFIG_FILE = os.path.join(SPLUNK_HOME, "etc", "log.cfg")
    LOGGING_LOCAL_CONFIG_FILE = os.path.join(SPLUNK_HOME, "etc", "log-local.cfg")
    LOGGING_STANZA_NAME = "python"
    LOGGING_FILE_NAME = "api_alerts.log"
    BASE_LOG_PATH = os.path.join("var", "log", "splunk")
    LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t%(module)s:%(lineno)d - {}: %(message)s".format(uuid)
    splunk_log_handler = logging.handlers.RotatingFileHandler(
        os.path.join(SPLUNK_HOME, BASE_LOG_PATH, LOGGING_FILE_NAME), mode="a"
    )
    splunk_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
    logger.addHandler(splunk_log_handler)
    setupSplunkLogger(logger, LOGGING_DEFAULT_CONFIG_FILE, LOGGING_LOCAL_CONFIG_FILE, LOGGING_STANZA_NAME)
    return logger
 
def main():
    alert_uuid = str(uuid.uuid4())
    logger = setup_logging(alert_uuid)
 
    if len(sys.argv) <= 1 or sys.argv[1] != "--execute":
        logger.critical("Unsupported execution mode (expected --execute flag)")
        sys.exit(1)
 
    payload = json.loads(sys.stdin.read())
    settings = payload.get("configuration")
 
    # Prompt user for API token
    while True:
        api_token = getpass.getpass("Enter API token: ")
        if input("Show API token? (y/n): ").strip().lower() == 'y':
            print(f"API token: {api_token}")
        if input("Is the API token correct? (y/n): ").strip().lower() == 'y':
            break
 
    # Choose the webhook URL
    while True:
        env = input("Choose the environment (prod/stage): ").strip().lower()
        if env in WEBHOOK_URLS:
            url = WEBHOOK_URLS[env]
            break
        else:
            print("Invalid environment. Please choose 'prod' or 'stage'.")
 
    headers = {
        "Authorization": api_token,
        "Content-Type": "application/json",
        "X-Request-Id": alert_uuid
    }
 
    data = json.dumps({
        "search_name": payload.get("search_name"),
        "result": payload.get("result"),
        "search_query": settings.get("search_query"),
    })
    encoded_data = encode(data)
    logger.info("Calling url='{}' with body='{}'".format(url, data))
    send_http_request(url, encoded_data, headers, logger, settings.get("proxy"))
 
if __name__ == "__main__":
    main()
