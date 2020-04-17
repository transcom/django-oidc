# coding: utf-8
from __future__ import unicode_literals

import logging
try:
    from builtins import unicode as str
except ImportError:
    pass

from django.conf import settings
from django.http import HttpResponseRedirect
from oic import oic, rndstr
from oic.exception import MissingAttribute
from oic.oauth2 import ErrorResponse, MissingEndpoint, ResponseError
from oic.oic import (AuthorizationRequest, AuthorizationResponse,
                     RegistrationResponse)
from oic.oic.message import ProviderConfigurationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils import keyio

from . import exceptions

__author__ = 'roland'

logger = logging.getLogger(__name__)

default_ssl_check = getattr(settings, 'OIDC_VERIFY_SSL', True)


class OIDCError(exceptions.OIDCException):
    pass


class Client(oic.Client):

    def __init__(self, client_id=None, ca_certs=None,
                 client_prefs=None, client_authn_method=None, keyjar=None,
                 verify_ssl=True, behaviour=None):
        oic.Client.__init__(self, client_id=client_id, client_authn_method=client_authn_method, keyjar=keyjar, verify_ssl=verify_ssl, config=client_prefs)
        if behaviour:
            self.behaviour = behaviour
        else:
            self.behaviour = {}

    def create_authn_request(self, session,  # *, - let's not use this fancy py3 thing for compatibility
                             acr_value=None, extra_args=None):
        session["state"] = rndstr(size=32)
        session["nonce"] = rndstr(size=32)
        request_args = {
            "response_type": self.behaviour["response_type"],
            "scope": self.behaviour["scope"],
            "state": session["state"],
            "nonce": session["nonce"],
            "redirect_uri": self.registration_response["redirect_uris"][0]
        }

        if acr_value is None:
            acr_value = self.behaviour.get('acr_value')

        if acr_value is not None:
            request_args["acr_values"] = acr_value

        if extra_args is not None:
            request_args.update(extra_args)
        cis = self.construct_AuthorizationRequest(request_args=request_args)
        logger.debug("request: %s" % cis)

        url, body, ht_args, cis = self.uri_and_body(AuthorizationRequest, cis,
                                                    method="GET",
                                                    request_args=request_args,)
        logger.debug("body: %s" % body)
        logger.info("URL: %s" % url)
        logger.debug("ht_args: %s" % ht_args)

        resp = HttpResponseRedirect(str(url))
        if ht_args:
            for key, value in ht_args.items():
                resp[key] = value
        logger.debug("resp_headers: %s" % ht_args)
        return resp

    def callback(self, response, session):
        """
        Should be called when an AuthN response has been received from the OP.

        :param response: The URL returned by the OP
        :return:
        """
        try:
            authresp = self.parse_response(AuthorizationResponse, response,
                                           sformat="dict", keyjar=self.keyjar)
        except ResponseError as e:
            return OIDCError(u"Response error: {}".format(e))

        if isinstance(authresp, ErrorResponse):
            if authresp["error"] == "login_required":
                return self.create_authn_request(session)
            else:
                return OIDCError("Access denied")

        if session["state"] != authresp["state"]:
            return OIDCError("Received state not the same as expected.")

        try:
            if authresp["id_token"] != session["nonce"]:
                return OIDCError("Received nonce not the same as expected.")
            self.id_token[authresp["state"]] = authresp["id_token"]
        except KeyError:
            pass

        if self.behaviour["response_type"] == "code":
            # get the access token
            try:
                args = {
                    "code": authresp["code"],
                    "redirect_uri": self.registration_response["redirect_uris"][0],
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                }

                atresp = self.do_access_token_request(
                    scope="openid", state=authresp["state"], request_args=args,
                    authn_method=self.registration_response["token_endpoint_auth_method"])
            except Exception as err:
                logger.error("%s" % err)
                raise

            if isinstance(atresp, ErrorResponse):
                raise OIDCError("Invalid response %s." % atresp["error"])
            session['id_token'] = atresp['id_token']._dict
            if session['id_token']:
                session['id_token_raw'] = getattr(self, 'id_token_raw', None)
            session['access_token'] = atresp['access_token']
            for k in ['refresh_token', 'expires_in']:
                try:
                    session[k] = atresp[k]
                except:
                    session[k] = ""
        try:
            inforesp = self.do_user_info_request(
                state=authresp["state"], method="GET")

            if isinstance(inforesp, ErrorResponse):
                raise OIDCError("Invalid response %s." % inforesp["error"])

            userinfo = inforesp.to_dict()

            logger.debug("UserInfo: %s" % inforesp)
        except MissingEndpoint as e:
            logging.warning("Wrong OIDC provider implementation or configuration: {}; using token as userinfo source".format(
                e
            ))
            userinfo = session.get('id_token', {})

        return userinfo

    def store_response(self, resp, info):
        # makes raw ID token available for internal means
        try:
            import json
            from oic.oic.message import AccessTokenResponse
            if isinstance(resp, AccessTokenResponse):
                info = json.loads(info)
                self.id_token_raw = info['id_token']
        except Exception as e:
            # fail silently if something is wrong
            logger.exception(e)

        super(Client, self).store_response(resp, info)

    def __repr__(self):
        return u"Client {} {} {}".format(
            self.client_id,
            self.client_prefs,
            self.behaviour,
        )


class OIDCClients(object):

    def __init__(self, config):
        """

        :param config: Imported configuration module
        :return:
        """
        self.client = {}
        self.client_cls = Client
        self.config = config

        for key, val in config.OIDC_PROVIDERS.items():
            if key == "":
                continue
            else:
                self.client[key] = self.create_client(**val)

    def create_client(self, userid="", **kwargs):
        """
        Do an instantiation of a client instance

        :param userid: An identifier of the user
        :param: Keyword arguments
            Keys are ["srv_discovery_url", "client_info", "client_registration",
            "provider_info"]
        :return: client instance
        """
        _key_set = set(kwargs.keys())
        args = {}
        for param in ["verify_ssl"]:
            try:
                args[param] = kwargs[param]
            except KeyError:
                pass
            else:
                _key_set.discard(param)

        try:
            verify_ssl = default_ssl_check
        except:
            verify_ssl = True

        # Check to see if there is a keyset specified in the client_registration (if it is a client_registration type)
        #   This gets used if the authentication method is "private_key_jwt
        if "client_registration" in _key_set:
            if "keyset_jwk_file" in kwargs["client_registration"].keys():
                key_bundle = keyio.keybundle_from_local_file(kwargs["client_registration"]["keyset_jwk_file"],"jwk","sig")
                key_jar =keyio.KeyJar(verify_ssl=verify_ssl)
                key_jar.add_kb("",key_bundle)
                args["keyjar"] = key_jar
            if "keyset_jwk_dict" in kwargs["client_registration"].keys():
                kc_rsa = keyio.KeyBundle(kwargs["client_registration"]['keyset_jwk_dict'])
                key_jar =keyio.KeyJar(verify_ssl=verify_ssl)
                key_jar.add_kb("",kc_rsa)
                args["keyjar"] = key_jar

        client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD,
                                 behaviour=kwargs["behaviour"], verify_ssl=verify_ssl, **args)

        # The behaviour parameter is not significant for the election process
        _key_set.discard("behaviour")
        for param in ["allow"]:
            try:
                setattr(client, param, kwargs[param])
            except KeyError:
                pass
            else:
                _key_set.discard(param)

        if _key_set == set(["client_info"]):  # Everything dynamic
            # There has to be a userid
            if not userid:
                raise MissingAttribute("Missing userid specification")

            # Find the service that provides information about the OP
            issuer = client.wf.discovery_query(userid)
            # Gather OP information
            client.provider_config(issuer)
            # register the client
            client.register(
                client.provider_info["registration_endpoint"],
                **kwargs["client_info"]
            )
        elif _key_set == set(["client_info", "srv_discovery_url"]):
            # Ship the webfinger part
            # Gather OP information
            client.provider_config(kwargs["srv_discovery_url"])
            # register the client
            client.register(
                client.provider_info["registration_endpoint"],
                **kwargs["client_info"]
            )
        elif _key_set == set(["provider_info", "client_info"]):
            client.handle_provider_config(
                ProviderConfigurationResponse(**kwargs["provider_info"]),
                kwargs["provider_info"]["issuer"])
            client.register(client.provider_info["registration_endpoint"],
                            **kwargs["client_info"])
        elif _key_set == set(["provider_info", "client_registration"]):
            client.handle_provider_config(
                ProviderConfigurationResponse(**kwargs["provider_info"]),
                kwargs["provider_info"]["issuer"])
            client.store_registration_info(RegistrationResponse(
                **kwargs["client_registration"]))
        elif _key_set == set(["srv_discovery_url", "client_registration"]):
            try:
                client.provider_config(kwargs["srv_discovery_url"])
                client.store_registration_info(
                    RegistrationResponse(**kwargs["client_registration"])
                )
            except Exception as e:
                logger.error(
                    "Provider info discovery failed for %s - assume backend unworkable",
                    kwargs["srv_discovery_url"]
                )
                logger.exception(e)
        else:
            raise Exception("Configuration error ?")

        return client

    def dynamic_client(self, userid):
        try:
            dyn = settings.OIDC_ALLOW_DYNAMIC_OP or False
        except:
            dyn = True
        if not dyn:
            raise KeyError("No dynamic clients allowed")

        client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD,
                                 verify_ssl=default_ssl_check)

        issuer = client.wf.discovery_query(userid)
        if issuer in self.client:
            return self.client[issuer]
        else:
            # Gather OP information
            _pcr = client.provider_config(issuer)
            # register the client
            client.register(_pcr["registration_endpoint"], **
                            self.config.OIDC_DYNAMIC_CLIENT_REGISTRATION_DATA)
            try:
                client.behaviour.update(**self.config.OIDC_DEFAULT_BEHAVIOUR)
            except KeyError:
                pass

            self.client[issuer] = client
            return client

    def __getitem__(self, item):
        """
        Given a service or user identifier return a suitable client
        :param item:
        :return:
        """
        try:
            return self.client[item]
        except KeyError:
            return self.dynamic_client(item)

    def keys(self):
        return self.client.keys()
