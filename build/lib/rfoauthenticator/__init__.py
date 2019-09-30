import json
import os
from urllib.parse import quote, urlparse
import requests
from tornado import gen, web
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from jupyterhub.utils import url_path_join
from jupyterhub.handlers import LoginHandler
from oauthenticator import OAuthCallbackHandler
from oauthenticator.auth0 import Auth0OAuthenticator, Auth0LoginHandler


AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
REFACTORED_ACCOUNTS_DOMAIN = os.getenv("REFACTORED_ACCOUNTS_DOMAIN")
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN")


class RFLoginHandler(LoginHandler):
    def get_next_url(self, user=None, default=None):
        """Get the next_url for login redirect
        Default URL after login:
        - if redirect_to_server (default): send to user's own server
        - else: /hub/home
        """
        next_url = self.get_argument("next", default="")
        # protect against some browsers' buggy handling of backslash as slash
        next_url = next_url.replace("\\", "%5C")
        if (next_url + "/").startswith(
            (
                "%s://%s/" % (self.request.protocol, self.request.host),
                "//%s/" % self.request.host,
            )
        ) or (
            self.subdomain_host
            and urlparse(next_url).netloc
            and ("." + urlparse(next_url).netloc).endswith(
                "." + urlparse(self.subdomain_host).netloc
            )
        ):
            # treat absolute URLs for our host as absolute paths:
            # below, redirects that aren't strictly paths
            parsed = urlparse(next_url)
            next_url = parsed.path
            if parsed.query:
                next_url = next_url + "?" + parsed.query
            if parsed.fragment:
                next_url = next_url + "#" + parsed.fragment

        if next_url and next_url.startswith(url_path_join(self.base_url, "user/")):
            # add /hub/ prefix, to ensure we redirect to the right user's server.
            # The next request will be handled by SpawnHandler,
            # ultimately redirecting to the logged-in user's server.
            without_prefix = next_url[len(self.base_url) :]
            next_url = url_path_join(self.hub.base_url, without_prefix)
            self.log.warning(
                "Redirecting %s to %s. For sharing public links, use /user-redirect/",
                self.request.uri,
                next_url,
            )

        if not next_url:
            # custom default URL
            next_url = default or self.default_url

        if not next_url:
            # default URL after login
            # if self.redirect_to_server, default login URL initiates spawn,
            # otherwise send to Hub home page (control panel)
            if user and self.redirect_to_server:
                if user.spawner.active:
                    # server is active, send to the user url
                    next_url = user.url
                else:
                    # send to spawn url
                    next_url = url_path_join(self.hub.base_url, "spawn")
            else:
                next_url = url_path_join(self.hub.base_url, "home")
        return next_url


class RFOAuthCallbackHandler(OAuthCallbackHandler):
    async def get(self):
        self.check_arguments()
        user = await self.login_user()
        if user is None:
            # todo: custom error page?
            raise web.HTTPError(403)
        url = "{}://{}{}".format(
            self.request.protocol, self.request.host, self.get_next_url(user)
        )
        url = "https://%s/postauth?next=%s" % (REFACTORED_ACCOUNTS_DOMAIN, quote(url))
        self.redirect(url)


class RFAuth0LoginHandler(Auth0LoginHandler):
    _OAUTH_AUTHORIZE_URL = "https://%s/authorize" % AUTH0_DOMAIN
    _OAUTH_ACCESS_TOKEN_URL = "https://%s/oauth/token" % AUTH0_DOMAIN


class RFAuth0OAuthenticator(Auth0OAuthenticator):
    callback_handler = RFOAuthCallbackHandler
    login_handler = RFAuth0LoginHandler

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        http_client = AsyncHTTPClient()
        params = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.get_callback_url(handler),
        }
        url = "https://%s/oauth/token" % AUTH0_DOMAIN

        req = HTTPRequest(
            url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(params),
            connect_timeout=60.0,
            request_timeout=60.0,
        )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode("utf8", "replace"))

        access_token = resp_json["access_token"]

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Bearer {}".format(access_token),
        }
        req = HTTPRequest(
            "https://%s/userinfo" % AUTH0_DOMAIN,
            method="GET",
            headers=headers,
            connect_timeout=60.0,
            request_timeout=60.0,
        )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode("utf8", "replace"))

        # set_user
        url = "https://%s/user/create?servicetoken=%s" % (
            REFACTORED_ACCOUNTS_DOMAIN,
            SERVICE_TOKEN,
        )
        e = resp_json["email"]
        r = requests.post(url, data={"email": e})
        d = r.json()
        ds100_users = {
            "dinesh@micropyramid.com": "druuu",
            "vamsich2019@gmail.com": "vamsireddy01",
            "arahman4a@yahoo.com": "aarahm3631",
            "ssiriyapureddy@yahoo.com": "sivaprasad94",
            "fmndicho@gmail.com": "ffmndi3648",
            "yaniktov@gmail.com": "yyanik5873",
            "Bynder.Enterprises@gmail.com": "jjonat5190",
            "mani@colaberry.com": "manirv",
            "pervillalva@hotmail.com": "ppervi8060",
            "athresa@gmail.com": "athresa1972",
            "amamun619@gmail.com": "aamamu2639",
            "zeeshanmehdi79@gmail.com": "zzeesh5273",
            "ali@colaberry.com": "aalico1008",
            "obidiaku@gmail.com": "oobidi4637",
            "kulateja27@gmail.com": "kkulat8205",
            "agease@gmail.com": "aageas3618",
            "soetantunde@gmail.com": "ssoeta3634",
            "lakshminvdwgl@gmail.com": "lakshmiwgl",
            "ganesh.manjramkar5@gmail.com": "ganeshm5",
            "sushovan.93@gmail.com": "sshova6054",
            "michaelp.nelson@yahoo.com": "mmicha8251",
            "michaelapresser@gmail.com": "mmicha8994",
            "sureshmarreddy99@gmail.com": "sureshmarreddy99",
            "vamsi.patnam93@gmail.com": "vamsipat",
            "vinodkumarg357@gmail.com": "vvinod9830",
            "numaandin@gmail.com": "numaandin",
            "jcadizas@gmail.com": "jjcadi9757",
            "hubertndifusah@rocketmail.com": "hhuber9681",
            "gsrikar@yahoo.com": "ggsrik1191",
            "nkfunjiyvetten@yahoo.com": "nnkfun4191",
            "balajidevulapalli@hotmail.com": "balajidevulapalli",
            "calvintendai@gmail.com": "ccalvi4695",
            "o439noah@yahoo.com": "oonoah7302",
            "hai.redfox@outlook.com": "hhaire4805",
            "shijiesheng113@gmail.com": "sshiji5846",
            "cgdillan1998@gmail.com": "ccgdil4001",
            "bonifacetongi@bonton.co.ke": "bbonif8663",
            "eklou79@yahoo.com": "eeklou9509",
            "andrew@colaberry.com": "aandre2040",
            "harsha.sidda@gmail.com": "hharsh8118",
            "kramyadav446@gmail.com": "kkramy3189",
            "souji.1990@gmail.com": "ssouji9906",
            "alexsharifian2010@gmail.com": "aalexs4424",
            "pmoemeka@hotmail.com": "ppmoem5776",
            "poosarla.dileep@gmail.com": "ppoosa3510",
            "supersunik@yahoo.com": "ssuper1092",
            "andrewrhanson1@gmail.com": "aandre9409",
            "sathwik@colaberry.com": "vsathwikm",
            "devathimaheshbabu@gmail.com": "ddevat5357",
            "tarunraze@gmail.com": "tarunsura",
            "abul@colaberry.com": "abulshariff",
            "shivaji@naidu.com": "sshiva1308",
            "nimisha.shah05@gmail.com": "nnimis4515",
            "samcuibo@gmail.com": "ssamcu8924",
            "sumirp77@gmail.com": "ssumir7454",
            "mathew.jimson@gmail.com": "mmathe6690",
            "lloyd.a.napier@gmail.com": "llloyd7341",
            "nnr.erp@gmail.com": "rajunnr",
            "nagarajuneeluri@gmail.com": "nnagar1493",
            "rchoi@nativo.net": "rryan9022",
            "serenerasheed@gmail.com": "sseren9008",
            "kiranvepa@gmail.com": "kkiran5590",
            "richa2211@gmail.com": "rricha3038",
            "ym8974434@outlook.com": "yymout7494",
            "ritahab050@gmail.com": "rritah2314",
            "pawan.nandakishore@gmail.com": "ppawan1522",
            "hopsonmika@gmail.com": "hhopso1985",
            "gaurav.khubchandani63@gmail.com": "ggaura2213",
            "ricarmorales@gmail.com": "rricar5284",
            "ramana.k@hotmail.com": "rkuchibh",
            "gregory.hassler@gmail.com": "ggrego2532",
            "emekaugama@gmyail.com": "eemeka5667",
            "anupathreya1@gmail.com": "aanupa9535",
            "test123@gmail.com": "ttestg7081",
            "rcannavielloabc@gmail.com": "rrcann4331",
            "rcannaviello123@gmail.com": "rrcann3427",
            "d3@d.com": "dddcom6342",
            "rcannavielloxyz@gmail.com": "rrcann2265",
            "kathraven@gmail.com": "kkathr4452",
            "cenaikoj@gmail.com": "ccenai3590",
            "yphrimpomaa@gmail.com": "yyphri5571",
            "bugley@me.com": "bbugle9399",
            "d2@d.com": "dddcom4755",
            "ashitkumar.nayak92@gmail.com": "aashit8236",
            "imkumarv@gmail.com": "iimkum3961",
            "suppiunna@gmail.com": "ssuppi1275",
            "makanju.yemi@gmail.com": "mmakan8119",
            "coeforan@gmail.com": "ccoefo1847",
            "durwasa.chakraborty@gmail.com": "ddurwa7506",
            "ratoncita207@yahoo.com": "rraton1410",
            "njeinstein@gmail.com": "nnatha2279",
            "sdelaney25@hotmail.com": "ssdela3137",
            "medonsalau@gmail.com": "mmedon4411",
            "rcannaviello@gmail.com": "rrcann9014",
            "hopsonmika@yahoo.com": "hhopso3374",
            "amikam.job.israel@gmail.com": "aamika4449",
            "arimeier@gmail.com": "aarime5824",
            "jen.looper@gmail.com": "jjenlo1972",
            "natalie@roughdraft.vc": "nnatal6017",
            "sperrye@gmail.com": "eemily9703",
            "joshua.paradise@gmail.com": "jjoshu2138",
            "ming.hu@namshi.com": "mmingh9122",
            "k.venky542@gmail.com": "kkvenk3019",
            "anudeep.bhaskar@gmail.com": "aanude1290",
            "tovarguille93@gmail.com": "ttovar5124",
            "dinesh+1@micropyramid.com": "ddines5100",
            "marvinmckinneyii@rocketmail.com": "mmarvi7482",
            "connorneal1992@gmail.com": "cconno1251",
            "nikhila@micropyramid.com": "nnikhi1532",
            "jomerad@gmail.com": "jjomer5711",
            "sneha@micropyramid.com": "ssneha3184",
            "seyoonjeong@gmail.com": "sseyoo9079",
            "raidu.g6@gmail.com": "ssubba1878",
            "anatoliy314@gmail.com": "aanato9647",
            "chani.02k@gmail.com": "cchani3248",
            "sashankg1@gmail.com": "ssasha8191",
            "mnguyen7@yahoo.com": "mmnguy8808",
            "ram@colaberry.com": "rramco9538",
            "ace395910@gmail.com": "aacegm8037",
            "abdulazeezjinad@gmail.com": "aabdul8163",
            "kwilton2001@yahoo.com": "kkwilt4258",
            "venkatesh.srilakshmi@gmail.com": "vvenka3844",
            "cjdaniels4@gmail.com": "cchuck3443",
            "stephen.wemple@gmail.com": "ssteph9612",
            "jcadizas02@gmail.com": "jjcadi9325",
            "low_ronald@outlook.com": "llowro1396",
            "suneet.taparia@gmail.com": "ssunee7476",
            "sravankodem@gmail.com": "ssrava2526",
            "sonalnd@gmail.com": "ssonal7216",
            "alexander.desroches@mail.mcgill.ca": "aalexa4697",
            "siri.prasad@gmail.com": "pprasa4478",
            "vishalpd19@gmail.com": "vvisha6036",
            "ajibadesamson365@yahoo.com": "aajiba9747",
            "vk508m@yandex.com": "vvkmya8789",
            "kkhanal16@winona.edu": "kkapil3302",
            "yixiaogong0104@gmail.com": "yyixia3165",
            "dineshmcmf@gmail.com": "ddines7137",
            "manikandan.rv@gmail.com": "manikandanrv",
            "Kulateja27@gmail.com": "xjhexghc",
            "ANAND@COLABERRY.COM": "ipjqomrf",
            "ali_muwwakkil@hotmail.com": "ujwkqbhc",
            "Jonathan.Bynder@gmail.com": "qzaemakk",
            "abdullahmamun_11@yahoo.com": "wyqejrzk",
            "kristina@colaberry.com": "uyfsmyht",
            "dinesh+3@micropyramid.com": "dine5362",
            "dinesh+4@micropyramid.com": "dine5364",
            "sumendar@gmail.com": "sume5365",
            "kranthiz@gmail.com": "kran5366",
            "miguel.ahv22@gmail.com": "migu5367",
            "archowdary.ae@gmail.com": "arch5369",
            "kenlogicus@gmail.com": "kenl5372",
            "seunolanipekun88@gmail.com": "seun5373",
            "celmore32@yahoo.com": "celm5375",
            "dinesh+33@micropyramid.com": "dine5378",
            "y.b.bezi@gmail.com": "ybbe5380",
            "ymei2@gmu.edu": "ymei5382",
        }
        n = ds100_users.get(e) or d["jupyter_username"]
        return {"name": n}

    def get_handlers(self, app):
        return [
            (r"/login", RFLoginHandler),
            (r"/oauth_login", self.login_handler),
            (r"/oauth_callback", self.callback_handler),
        ]
