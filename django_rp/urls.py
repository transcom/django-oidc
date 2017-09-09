from os import path

from django.conf.urls import include, patterns, url
from django.contrib import admin

admin.autodiscover()


BASEDIR = path.dirname(path.abspath(__file__))

urlpatterns = patterns('',
                       # URLS for OpenId authentication
                       url(r'openid/', include('djangooidc.urls')),

                       # Test URLs
                       url(r'^$', 'testapp.views.home', name='home'),
                       url(r'^unprotected$', 'testapp.views.unprotected', name='unprotected'),

                       # Uncomment the next line to enable the admin:
                       url(r'^admin/', include(admin.site.urls)),

                       )
