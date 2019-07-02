import json
import os
from tornado.auth import OAuth2Mixin
from tornado import gen, web
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from oauthenticator.auth0 import Auth0OAuthenticator


AUTH0_SUBDOMAIN = os.getenv('AUTH0_SUBDOMAIN')
REFACTORED_ACCOUNTS_DOMAIN = os.getenv('REFACTORED_ACCOUNTS_DOMAIN')

class RFAuth0OAuthenticator(Auth0OAuthenticator):
    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        http_client = AsyncHTTPClient()
        params = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code':code,
            'redirect_uri': self.get_callback_url(handler)
        }
        url = "https://%s.auth0.com/oauth/token" % AUTH0_SUBDOMAIN

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Content-Type": "application/json"},
                          body=json.dumps(params),
                          connect_timeout=60.0,
                          request_timeout=60.0,
                          )
        
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        
        access_token = resp_json['access_token']
        
        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
                 "Authorization": "Bearer {}".format(access_token)
        }
        req = HTTPRequest("https://%s.auth0.com/userinfo" % AUTH0_SUBDOMAIN,
                          method="GET",
                          headers=headers,
                          connect_timeout=60.0,
                          request_timeout=60.0,
                          )
        resp = yield http_client.fetch(req)
        print('resp >>', resp)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        print('resp_json >>', resp_json)

        # set_user
        url = "https://%s/user/create" % settings.REFACTORED_ACCOUNTS_DOMAIN
        d = {"email": email}
        headers={"Accept": "application/json"}
        req = HTTPRequest(
                url,
                method="POST",
                body=json.dumps(d),
                headers=headers,
                connect_timeout=60.0,
                request_timeout=60.0,
        )
        resp = yield http_client.fetch(req)
        print('>>>>>>>>>>>>>>> set_user', email)
        print(resp)
        print(resp.body)
        d = json.loads(resp.body.decode('utf8', 'replace'))
        print(d)
        return {
            'name': d['username']
        }
