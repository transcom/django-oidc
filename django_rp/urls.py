from os import path

from django.conf.urls import include, url
from django.contrib import admin

from testapp.views import home, unprotected

admin.autodiscover()


BASEDIR = path.dirname(path.abspath(__file__))

urlpatterns = [
   # URLS for OpenId authentication
   url(r'^openid/', include('djangooidc.urls')),

   # Test URLs
   url(r'^$', home, name='home'),
   url(r'^unprotected$', unprotected, name='unprotected'),

   # Uncomment the next line to enable the admin:
   url(r'^admin/', admin.site.urls),
]
