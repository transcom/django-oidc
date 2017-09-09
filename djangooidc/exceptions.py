

from djangooidc import status


class OIDCException(Exception):
    """
    Base class for django oidc  exceptions.
    Subclasses should provide `.status_code` and `.default_detail` properties.
    """
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'A server error occurred.'
    default_code = 'error'

    def __init__(self, detail=None, code=None):
        if detail is None:
            detail = self.default_detail
        if code is None:
            code = self.default_code
        self.code = code
        self.detail = detail

    def __str__(self):
        return self.detail


class AuthenticationFailed(OIDCException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'Incorrect authentication credentials.'
    default_code = 'authentication_failed'


# class ConfigurationError(OIDCException):
#     status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
#     default_detail = 'Configuration error.'
#     default_code = 'configuration_error'


# class ResponseError(OIDCException):
#     status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
#     default_detail = 'Response error.'
#     default_code = 'response_error'


# class CallbackStateMismatchError(OIDCException):
#     status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
#     default_detail = 'Callback state mismatch error.'
#     default_code = 'callback_state_error'
