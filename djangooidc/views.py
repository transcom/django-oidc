# coding: utf-8

import logging
from urllib.parse import parse_qs, urlencode

from django import forms
from django.conf import settings
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import login as auth_login_view
from django.contrib.auth.views import logout as auth_logout_view
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import redirect, render_to_response, resolve_url
from djangooidc.oidc import OIDCClients, OIDCError

from . import exceptions

logger = logging.getLogger(__name__)

CLIENTS = OIDCClients(settings)


def template_view_error(request, ctx, **kwargs):
    return render_to_response("djangooidc/error.html", ctx)


view_error_handler = template_view_error


# Step 1: provider choice (form). Also - Step 2: redirect to OP. (Step 3
# is OP business.)


class DynamicProvider(forms.Form):
    hint = forms.CharField(
        required=True, label='OpenID Connect full login', max_length=250)


def openid(request, op_name=None):
    client = None
    request.session["next"] = request.GET[
        "next"] if "next" in request.GET.keys() else "/"
    try:
        dyn = settings.OIDC_ALLOW_DYNAMIC_OP or False
    except:
        dyn = True

    try:
        template_name = settings.OIDC_LOGIN_TEMPLATE
    except AttributeError:
        template_name = 'djangooidc/login.html'

    # Internal login?
    if request.method == 'POST' and "internal_login" in request.POST:
        ilform = AuthenticationForm(request.POST)
        return auth_login_view(request)
    else:
        ilform = AuthenticationForm()

    # Try to find an OP client either from the form or from the op_name URL
    # argument
    if request.method == 'GET' and op_name is not None:
        try:
            client = CLIENTS[op_name]
        except KeyError as e:
            logger.info(str(e))
            raise Http404("OIDC client not found")
        request.session["op"] = op_name

    if request.method == 'POST' and dyn:
        form = DynamicProvider(request.POST)
        if form.is_valid():
            try:
                client = CLIENTS.dynamic_client(form.cleaned_data["hint"])
                request.session["op"] = client.provider_info["issuer"]
            except Exception as e:
                logger.exception("could not create OOID client")
                return view_error_handler(request, {"error": e})
    else:
        form = DynamicProvider()

    # If we were able to determine the OP client, just redirect to it with an
    # authentication request
    if client:
        try:
            return client.create_authn_request(request.session)
        except Exception as e:
            return view_error_handler(request, {"error": e})

    # Otherwise just render the list+form.
    return render_to_response(template_name,
                              {"op_list": [i for i in settings.OIDC_PROVIDERS.keys() if i], 'dynamic': dyn,
                               'form': form, 'ilform': ilform, "next": request.session["next"]})


# Step 4: analyze the token returned by the OP
def authz_cb(request):
    op = request.session.get("op")
    if op is None:
        # client session has been dropped or never existed - just ask him to do
        # it again
        return view_error_handler(request, {
            "error": 'Wrong authentication; Please try again',
            "callback": None
        })
    client = CLIENTS[request.session["op"]]
    query = None

    try:
        query = parse_qs(request.GET.urlencode())
        callback_result = client.callback(query, request.session)
        if isinstance(callback_result, OIDCError):
            raise callback_result
        userinfo = callback_result
        request.session["userinfo"] = userinfo
        user = authenticate(request=request, **userinfo)
        if user:
            login(request, user)
            return redirect(request.session.get("next", "/"))
        else:
            raise exceptions.AuthenticationFailed(
                'this login is not valid in this application')
    except OIDCError as e:
        return view_error_handler(request, {"error": e, "callback": query})


def logout(request, next_page=None):
    # User is by default NOT redirected to the app - it stays on an OP page after logout.
    # Here we determine if a redirection to the app was asked for and is
    # possible.
    if next_page is None and "next" in request.GET.keys():
        next_page = request.GET['next']
    if next_page is None and "next" in request.session.keys():
        next_page = request.session['next']
    if next_page is None:
        next_page = getattr(settings, 'LOGOUT_REDIRECT_URL', None)

    if "op" not in request.session.keys():
        return auth_logout_view(request, next_page)

    client = None
    try:
        client = CLIENTS[request.session["op"]]
    except KeyError:
        logger.info("OIDC client {} not found".format(request.session["op"]))

    extra_args = {}
    if client is not None and "post_logout_redirect_uris" in client.registration_response.keys() and len(
            client.registration_response["post_logout_redirect_uris"]) > 0:
        if next_page is not None:
            # First attempt a direct redirection from OP to next_page
            next_page_url = resolve_url(next_page)
            urls = [url for url in client.registration_response[
                "post_logout_redirect_uris"] if next_page_url in url]
            if len(urls) > 0:
                extra_args["post_logout_redirect_uri"] = urls[0]
            else:
                # It is not possible to directly redirect from the OP to the page that was asked for.
                # We will try to use the redirection point - if the redirection
                # point URL is registered that is.
                next_page_url = resolve_url('openid_logout_cb')
                urls = [url for url in client.registration_response["post_logout_redirect_uris"] if
                        next_page_url in url]
                if len(urls) > 0:
                    extra_args["post_logout_redirect_uri"] = urls[0]
                else:
                    # Just take the first registered URL as a desperate attempt
                    # to come back to the application
                    extra_args["post_logout_redirect_uri"] = client.registration_response["post_logout_redirect_uris"][
                        0]
    else:
        # No post_logout_redirect_uris registered at the OP - no redirection to
        # the application is possible anyway
        pass

    # Redirect client to the OP logout page
    try:
        # DP HACK: Needed to get logout to actually logout from the OIDC Provider
        # According to ODIC session spec (http://openid.net/specs/openid-connect-session-1_0.html#RPLogout)
        # the user should be directed to the OIDC provider to logout after being
        # logged out here.

        if 'access_token' in request.session and 'state' in request.session:
            # TODO: determine if OIDC was used to login by some better way

            request_args = {
                'id_token_hint': request.session['access_token'],
                'state': request.session['state'],
            }
            # should include the post_logout_redirect_uri
            request_args.update(extra_args)

            url = client.provider_info['end_session_endpoint']
            url += "?" + urlencode(request_args)
            return HttpResponseRedirect(url)

            # Looks like they are implementing back channel logout, without checking for
            # support?
            # http://openid.net/specs/openid-connect-backchannel-1_0.html#Backchannel
            """
            request_args = None
            if 'id_token' in request.session.keys():
                request_args = {'id_token': IdToken(**request.session['id_token'])}
            res = client.do_end_session_request(state=request.session["state"],
                                                extra_args=extra_args, request_args=request_args)
            content_type = res.headers.get("content-type", "text/html") # In case the logout response doesn't set content-type (Seen with Keycloak)
            resp = HttpResponse(content_type=content_type, status=res.status_code, content=res._content)
            for key, val in res.headers.items():
                resp[key] = val
            return resp
            """
    finally:
        # Always remove Django session stuff - even if not logged out from OP.
        # Don't wait for the callback as it may never come.
        auth_logout(request)
        if next_page:
            request.session['next'] = next_page

    return HttpResponseRedirect(next_page)


def logout_cb(request):
    """Simple redirection view: after logout, just redirect to a parameter value inside the session"""
    next = request.session["next"] if "next" in request.session.keys() else "/"
    return redirect(next)
