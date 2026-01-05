import logging
import json
import os
import requests
import sys


def error(message, logger=None, code=os.EX_UNAVAILABLE):
    print("ERROR: " + message, file=sys.stderr)
    if logger is not None:
        logger.error(message)
    sys.exit(code)


class Connection:

    def __init__(self, config, logger=None):
        if logger is None:
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger
        for i in ('url', 'username', 'passwordfile',):
            if i not in config:
                error(f"Need {i} in config")
            setattr(self, i, config[i])
        self._session = requests.Session()
        self.update_token()

    def get(self, path: str) -> requests.Response:
        """Uses requests to make a get request."""
        return self._request_wrapper("get", path)

    def get_list(self, path: str) -> requests.Response:
        """Uses requests to make a get request.
           Will iterate over paginated results and return result as list."""
        ret = []
        while path:
            result = self.get(path).json()
            if 'next' in result:
                path = result['next']
                ret.extend(result['results'])
            else:
                path = None
        return ret

    def post(self, path: str, data) -> requests.Response:
        """Uses requests to make a post request. Assumes that all kwargs are
        data fields"""

        return self._request_wrapper("post", path, data)

    def patch(self, path: str, data) -> requests.Response:
        """Uses requests to make a patch request. Assumes that all kwargs are data
        fields"""
        return self._request_wrapper("patch", path, data)

    def delete(self, path: str) -> requests.Response:
        """Uses requests to make a delete request."""
        return self._request_wrapper("delete", path)

    def result_check(self, result, type, url, data=None):
        if not result.ok:
            message = f"{type} \"{url}\": {result.status_code}: {result.reason}"
            try:
                body = result.json()
            except ValueError:
                pass
            else:
                message += "\n{}".format(json.dumps(body, indent=2))
                if data is not None:
                    message += "\n{}".format(json.dumps(data, indent=2))
            error(message, logger=self.logger)

    def _request_wrapper(self, type, path, data=None, first=True):
        headers = {'content-type': 'application/json'}
        url = requests.compat.urljoin(self.url, path)
        jsondata = json.dumps(data)
        self.logger.info("%s %s", type.upper(), url)
        result = getattr(self._session, type)(url, data=jsondata, headers=headers)

        if first and result.status_code == 401:
            self.update_token()
            return self._request_wrapper(type, path, data=data, first=False)

        self.result_check(result, type.upper(), url, data=data)
        return result

    def read_passwordfile(self):
        try:
            with open(self.passwordfile, 'r') as f:
                password = f.readline().strip()
        except (FileNotFoundError, EOFError) as e:
            error(f"{e}", code=e.errno)
        return password

    def update_token(self):
        tokenurl = requests.compat.urljoin(self.url, "/api/token-auth/")
        data = {'username': self.username, 'password': self.read_passwordfile()}
        result = requests.post(tokenurl, data)
        self.result_check(result, "post", tokenurl)
        token = result.json()['token']
        self._session.headers.update({"Authorization": f"Token {token}"})
