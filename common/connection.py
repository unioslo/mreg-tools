import json
import requests


def error(message):
    print(message)
    import sys
    sys.exit(1)
    

class Connection:

    def __init__(self, config):
        for i in ('url', 'username', 'password',):
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
            result = self._request_wrapper("get", path).json()
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

    @staticmethod
    def result_check(result, type, url, data=None):
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
            error(message)

    def _request_wrapper(self, type, path, data=None, first=True):
        headers = {'content-type': 'application/json'}
        url = requests.compat.urljoin(self.url, path)
        jsondata = json.dumps(data)
        result = getattr(self._session, type)(url, data=jsondata, headers=headers)

        if first and result.status_code == 401:
            self.update_token()
            return self._request_wrapper(type, path, data=data, first=False)

        self.result_check(result, type.upper(), url, data=data)
        return result

    def update_token(self):
        tokenurl = requests.compat.urljoin(self.url, "/api/token-auth/")
        data = {'username': self.username, 'password': self.password}
        result = requests.post(tokenurl, data)
        self.result_check(result, "post", tokenurl)
        token = result.json()['token']
        self._session.headers.update({"Authorization": f"Token {token}"})
