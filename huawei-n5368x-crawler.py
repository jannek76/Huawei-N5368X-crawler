#!/usr/bin/env python
import sys
import uuid
import hashlib
import hmac
import json
import datetime
import logging
import time
import requests
import hiyapyco
import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from time import sleep
from binascii import hexlify
from flatten_json import flatten
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

from tenacity import retry, stop_after_delay, wait_fixed, stop_after_attempt
from functools import partial

# Load used configurations from `settings.yml` and overdrive values
# from `settings-overdrive.yml`
conf = hiyapyco.load('settings.yml', 'settings-overdrive.yml', failonmissingfiles=False)

time_now = datetime.datetime.utcnow()

# Settings
ROUTER = conf['ROUTER']                          # Router IP address
USER = conf['USER']                              # Router username
PASSWORD = str.encode(conf['PASSWORD'])          # Router password converts str to bytes
LOG_LEVEL = conf['LOG_LEVEL']                    # Logging level
TIME_BETWEEN_CALLS = conf['TIME_BETWEEN_CALLS']  # Time between sequential calls, (seconds)
RETRIES = conf['RETRIES']                        # how many time retry
RETRY_INTERVAL = conf['RETRY_INTERVAL']          # wait time between retry call seconds

USEINFLUX = conf['INFLUXDB']['USEINFLUX']        # Whether to use Influx DB or not, set True or False

# Setup Influx database details in case that is used
if USEINFLUX:
    ifurl = conf['INFLUXDB']['ifurl']
    iftoken = conf['INFLUXDB']['iftoken']
    iforg = conf['INFLUXDB']['iforg']
    ifbucket = conf['INFLUXDB']['ifbucket']

# Define shorthand decorator for the used settings.
retry_on__error = partial(
    retry,
    stop=(stop_after_delay(10) | stop_after_attempt(RETRIES)),  # max. 10 seconds wait.
    wait=wait_fixed(RETRY_INTERVAL),  # wait 400ms
)()

logging.basicConfig(stream=sys.stdout, level=getattr(logging, LOG_LEVEL))


class InfluxDB:

    def __init__(self, url, token, org, write_options=SYNCHRONOUS):
        self.ifclient = InfluxDBClient(url=url, token=token, org=org)
        self.write_api = self.ifclient.write_api(write_options=write_options)

    """
    Close client
    """
    def logout(self):
        self.write_api.__del__()
        self.ifclient.__del__()

    # Write to Influx
    @retry_on__error
    def influxwrite(self, result, apiurl):
        fields = flatten(json.loads(result))

        body = {
                "measurement": apiurl.split('/')[1],
                "time": time_now,
                "fields": fields
        }

        logging.info('write to Influx: {}'.format(body))
        ifpoint = Point.from_dict(body)
        self.write_api.write(bucket=ifbucket, record=ifpoint)


class Huawei_N5368:

    def __init__(self, server, user, password):
        self.client = requests.Session()
        self.server = server
        self.user = user
        self.password = password
        self.router_token = []
        self.response2 = {}
        self.influxdb = InfluxDB(ifurl, iftoken, iforg)  if USEINFLUX else None
        self.previous_calltime = 0

    @retry_on__error
    def login(self):
        logging.debug('start login')
        self._login()
        logging.debug('logged In')

    # Logout
    def logout(self):
        logging.debug('start logout')
        payload = {'status': '0'}
        headers = {'requestverificationtoken': self._get_server_token()}
        url = "http://%s/api/login/login_out" % self.server
        self.client.post(url,
                         data=json.dumps(payload),
                         headers=headers,
                         cookies=self.response2.cookies)

        if self.influxdb:
            self.influxdb.logout()
        logging.debug('logged OUT')

    # Calling router API
    def getapicall(self, apiurl):
        self._wait_until_next_call()
        result = self._getapicall(apiurl)
        self.previous_calltime = time.time()
        if USEINFLUX:
            self.influxdb.influxwrite(result, apiurl)

    # POST to router API
    def postapicall(self, apiurl):
        self._wait_until_next_call()
        result = self._postapicall(apiurl)
        self.previous_calltime = time.time()

        if USEINFLUX:
            self.influxdb.influxwrite(result, apiurl)

    def _wait_until_next_call(self):
        cur_time = time.time()  # time object

        if cur_time < (self.previous_calltime + TIME_BETWEEN_CALLS):
            sleep(TIME_BETWEEN_CALLS - (cur_time-self.previous_calltime))

    @retry_on__error
    def _getapicall(self, apiurl):
        logging.info('_getapicall: {}'.format(apiurl))
        url = "http://%s/api/%s" % (self.server, apiurl)
        headers = {
            'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'requestverificationtoken': self._get_server_token()
        }
        result = self.client.get(url, headers=headers, cookies=self.response2.cookies).text
        logging.debug(result)
        return result

    @retry_on__error
    def _postapicall(self, apiurl):
        logging.info('_postapicall: {}'.format(apiurl))
        pubkey = self._get_pubkey()

        payloadstr = json.dumps(self._postpayload(apiurl)).encode('utf8')
        key = RSA.import_key(pubkey)
        encryptor = PKCS1_OAEP.new(key)
        encrypted = encryptor.encrypt(payloadstr)

        base64_bytes = base64.b64encode(encrypted)
        base64_message = base64_bytes.decode('utf-8')

        headers = {'requestverificationtoken': self._get_server_token()}
        url = "http://%s/api/%s" % (self.server, apiurl)
        result = self.client.post(url, data=base64_message, headers=headers,
                                  cookies=self.response2.cookies).text

        logging.debug(result)
        return result

    # Login to router using SCRAM and fetch wanted data
    def _login(self):
        # Setup session
        self._setup_session()
        self.router_token.append("INITIALIZE")

        # Get server token

        # Collect login challenge
        url = "http://%s/api/login/login_challenge" % self.server
        clientnonce = self._generate_nonce()
        firstnonce = clientnonce
        payload = {
            'username': self.user,
            'firstnonce': firstnonce
        }
        headers = {'requestverificationtoken': self._get_server_token()}
        response = self.client.post(url,
                                    data=json.dumps(payload),
                                    headers=headers)

        servernonce = json.loads(response.text)["servernonce"]
        salt = json.loads(response.text)["salt"]
        iterations = json.loads(response.text)["iterations"]

        # Get client proof
        clientproof = self._get_client_proof(
            clientnonce, servernonce, self.password,
            salt, iterations).decode('UTF-8')

        # Authenticate
        payload = {
            'clientproof': clientproof,
            'finalnonce': servernonce
        }
        headers = {
            'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'requestverificationtoken': self._get_server_token()
        }
        url = "http://%s/api/login/login_auth" % self.server
        self.response2 = self.client.post(url,
                                          data=json.dumps(payload),
                                          headers=headers,
                                          cookies=response.cookies)

        # Update token

        # Finalize login
        payload = {
            'status': '0'
        }
        headers = {'requestverificationtoken': self._get_server_token()}
        url = "http://%s/api/login/login_done" % self.server
        self.response2 = self.client.post(url,
                                          data=json.dumps(payload),
                                          headers=headers,
                                          cookies=self.response2.cookies)

        # Reset tokens
        del self.router_token
        self.router_token = []
        self.router_token.append("INITIALIZE")

    # Get session cookie
    def _setup_session(self):
        url = "http://%s/" % self.server
        response = self.client.get(url)
        response.raise_for_status()
        sleep(1)

    # Generate clientside nonce
    def _generate_nonce(self):
        return uuid.uuid4().hex + uuid.uuid4().hex

    # Get server token
    def _get_server_token(self):
        self.router_token.pop(0)
        if len(self.router_token) < 1:
            url = "http://%s/api/web/crsf_token" % self.server
            token_response = self.client.get(url).text
            self.router_token = json.loads(token_response)["tokens"].split(',')
        return self.router_token[0]

    # Calculate server-client proof, part of SCRAM algorithm
    def _get_client_proof(
            self, clientnonce, servernonce, password, salt, iterations):

        msg = "%s,%s,%s" % (clientnonce, servernonce, servernonce)
        salted_pass = hashlib.pbkdf2_hmac(
            'sha256', password, bytearray.fromhex(salt), iterations)
        client_key = hmac.new(b'Client Key', msg=salted_pass,
                              digestmod=hashlib.sha256)
        stored_key = hashlib.sha256()
        stored_key.update(client_key.digest())
        signature = hmac.new(msg.encode('utf_8'),
                             msg=stored_key.digest(), digestmod=hashlib.sha256)
        client_key_digest = client_key.digest()
        signature_digest = signature.digest()
        client_proof = bytearray()
        i = 0
        while i < client_key.digest_size:
            client_proof.append(client_key_digest[i] ^ signature_digest[i])
            i = i + 1

        return hexlify(client_proof)

    def _get_pubkey(self):
        url = "http://%s/api/web/pubkey" % self.server
        headers = {
            'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'requestverificationtoken': self._get_server_token()
        }
        pubkey_response = self.client.get(url,
                                          headers=headers,
                                          cookies=self.response2.cookies).text
        root = json.loads(pubkey_response)["pubkey"]
        return root

    def _postpayload(self, apiurl):
        if apiurl == 'modemmng/queryModemMonitorWithName':
            payload = {
                'monitorName': 'dataFlow',
                'argJson': {}
            }
        elif apiurl == 'modemmng/queryModemIMSI':
            payload = {
                    'monitorName': 'protocolStatus',
                    'argJson': {'cmd': 'IMSI'}
            }

        elif apiurl == 'modemmng/queryModemIMEI':
            payload = {
                    'monitorName': 'protocolStatus',
                    'argJson': {'cmd': 'IMEI'}
            }
        elif apiurl == 'equipservice/getequippara':
            payload = {
                    'ParaName': 'SNEX'
            }

        return payload


def main():
    """ main method """
    huawei = Huawei_N5368(ROUTER, USER, PASSWORD)
    huawei.login()

    huawei.getapicall('modemmng/getAntennaConfiguration')
    huawei.getapicall('modemmng/getSignal')
    huawei.getapicall('modemmng/getNrAirStat')
    huawei.getapicall('signalmng/getsiglevel')
    huawei.getapicall('web/uptime')
    huawei.getapicall('device/version')

    huawei.postapicall('modemmng/queryModemMonitorWithName')
    huawei.postapicall('modemmng/queryModemIMEI')
    huawei.postapicall('modemmng/queryModemIMSI')
    huawei.postapicall('equipservice/getequippara')

    huawei.logout()


if __name__ == "__main__":
    sys.exit(main())
