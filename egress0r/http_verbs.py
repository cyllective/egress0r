import io
import json
import socket
import traceback
import urllib.parse

import requests
import urllib3

from egress0r.message import PositiveMessage, NegativeMessage


class HTTPVerbsCheck:
    """Exfiltrate sample data via various HTTP verbs."""

    DEFAULT_TIMEOUT = 5
    START_MESSAGE = 'Performing various HTTP verb specific exfil tests...'

    def __init__(self, verbs, urls, exfil_payload, timeout=DEFAULT_TIMEOUT,
                 proxies=None, ssl_verify=False):
        self.verbs = verbs
        self.urls = urls
        self.exfil_payload = exfil_payload
        self.proxies = proxies
        self.timeout = timeout
        self.ssl_verify = ssl_verify
        self._session = self.configure_session(
            timeout=timeout,
            proxies=proxies,
            ssl_verify=ssl_verify
        )
        self._ignored_exceptions = (
            TypeError,
            KeyError,
            AttributeError,
            socket.gaierror,
            socket.timeout,
            requests.exceptions.RequestException,
            json.decoder.JSONDecodeError
        )

    def configure_session(self, timeout=None, proxies=None, ssl_verify=False):
        """Configure the requests session with the given parameters.
        This session is used for all HTTP verbs (all requests).
        """
        s = requests.Session()
        if ssl_verify is False:
            urllib3.disable_warnings()
        s.verify = ssl_verify
        s.proxies = proxies
        s.timeout = timeout
        return s

    def post_exfil(self, url, payload):
        """Exfiltrate the payload via POST."""
        try:
            r = self._session.post(url, files={'exfil': payload.to_io()})
            return payload.data == r.json()['files']['exfil']
        except self._ignored_exceptions:
            return False

    def put_exfil(self, url, payload):
        """Exfiltrate the payload via PUT."""
        data = payload.data
        try:
            r = self._session.put(url, data={'exfil': data})
            return data == r.json()['form']['exfil']
        except self._ignored_exceptions:
            #traceback.print_exc()
            return False

    def patch_exfil(self, url, payload):
        """Exfitrate the payload via PATCH."""
        data = payload.data
        try:
            r = self._session.patch(url, data={'exfil': data})
            return data == r.json()['form']['exfil']
        except self._ignored_exceptions:
            #traceback.print_exc()
            return False

    def get_exfil(self, url, payload):
        """Exfiltrate data via GET request.
        The payload is url encoded and appended to the URL as a parameter: ?exfil={payload}
        """
        lines = payload.data.split('\n')
        if len(lines) > 3:
            lines = lines[:3]

        partial_status = []
        for line in lines:
            url_encoded_line = urllib.parse.quote_plus(line)
            try:
                r = self._session.get(f'{url}?exfil={url_encoded_line}')
                status = line in r.text
                partial_status.append(status)
            except self._ignored_exceptions:
                #traceback.print_exc()
                return False
        return len(partial_status) == len(lines) and all(partial_status)

    def delete_exfil(self, url, payload):
        """Exfiltrate data via DELETE request.
        The payload is url encoded and appended to the URL as a parameter.
        """
        lines = payload.data.split('\n')
        if len(lines) > 3:
            lines = lines[:3]

        partial_status = []
        for line in lines:
            url_encoded_line = urllib.parse.quote_plus(line)
            try:
                r = self._session.delete(f'{url}?exfil={url_encoded_line}')
                status = line in r.text
                partial_status.append(status)
            except self._ignored_exceptions:
                #traceback.print_exc()
                return False
        return len(partial_status) == len(lines) and all(partial_status)


    def _to_message(self, status, verb, url, proxy=False):
        """Build a positive or negative Message object. Depending on status the
        returned object is either a PositiveMessage or NegativeMessage."""
        fail_message = f'Failed to exfiltrate data to {url} using {verb}'
        success_message = f'Exfiltrated data to {url} using {verb}'
        if proxy:
            fail_message += ' via proxy'
            success_message += ' via proxy'
        if status is True:
            return PositiveMessage(message=success_message)
        return NegativeMessage(message=fail_message)

    def check(self):
        call_map = {'GET': self.get_exfil,
                    'POST': self.post_exfil,
                    'PATCH': self.patch_exfil,
                    'PUT': self.put_exfil,
                    'DELETE': self.delete_exfil}
        for url in self.urls:
            for verb, func in call_map.items():
                if verb in self.verbs:
                    status = func(url + verb.lower(), self.exfil_payload)
                    yield self._to_message(status, verb, url, proxy=False)
                    if self.proxies is not None:
                        status = func(url + verb.lower(), self.exfil_payload, with_proxy=True)
                        yield self._to_message(status, verb, url, proxy=True)
