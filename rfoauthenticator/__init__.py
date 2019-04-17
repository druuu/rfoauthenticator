import json
import os
from tornado.auth import OAuth2Mixin
from tornado import gen, web
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from oauthenticator.auth0 import Auth0OAuthenticator


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
                          body=json.dumps(params)
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
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return {
            'name': resp_json["https://refactored.ai/sso_user"],
            'auth_state': {
                'access_token': access_token,
                'auth0_user': resp_json,
            }
        }
