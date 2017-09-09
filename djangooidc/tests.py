from django.test import TestCase

from djangooidc import *  # NOQA
from djangooidc.backends import *  # NOQA
from djangooidc.oidc import *  # NOQA
from djangooidc.urls import *  # NOQA
from djangooidc.views import *  # NOQA


class SmokeImportTest(TestCase):

    def test_smoke_import(self):
        # pass if imports on module level are fine
        return
