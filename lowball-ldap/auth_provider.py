from lowball.models.provider_models.auth_provider import AuthProvider, AuthPackage
from lowball.models.authentication_models import ClientData
from lowball.exceptions import MalformedAuthPackageException, InvalidCredentialsException


class LDAPAuthProvider(AuthProvider):
    """Default Auth Provider for Lowball Applications
    This is the primary class for the lowball-ldap Authentication Provider.
    :param username: the username of service account able to lookup and validate users.
    :type username: str
    :param password: the password of the service account.
    :type password: str
    """

    def _build_filter(self, username):
        pass

    def _auth_user(self, username, password):
        pass

    def _do_lookup(self, user_name):
        pass

    def __init__(self,
                 service_account,
                 service_account_password,
                 hostname,
                 base_dn,
                 domain,
                 username_attribute,
                 port=None,
                 protocol="ldap",
                 roll_mappings={}
                 ):

        super(LDAPAuthProvider, self).__init__()

        if not isinstance(service_account, str):
            raise TypeError("username must be a string")
        self._service_account = service_account

        if not isinstance(service_account_password, str):
            raise TypeError("password must be a string")
        self._service_account_password = service_account_password



    @property
    def username(self):
        """Get the username needed for authentication"""
        return self._username

    @username.setter
    def username(self, value):
        """Can't set username after init"""
        raise PermissionError("cannot set username after init")

    @property
    def password(self):
        """Get the password needed for authentication"""
        return self._password

    @password.setter
    def password(self, value):
        """Can't set password after init"""
        raise PermissionError("cannot set password after init")

    def authenticate(self, auth_package):
        """Authenticate a user.
        something something
        :param auth_package: data needed to authenticate with this provider
        :type auth_package: DefaultAuthPackage
        :return: auth data
        :rtype: AuthData
        """
        pass

    def get_client(self, client_id):
        pass

    @property
    def auth_package_class(self):
        """The auth package class that this class' `authenticate` method accepts."""
        return LDAPAuthPackage


class LDAPAuthPackage(AuthPackage):
    def __init__(self, username, password, **kwargs):
        super(LDAPAuthPackage, self).__init__(**kwargs)
        self.username = username
        self.password = password

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        if not isinstance(value, str):
            raise TypeError("username must be a string")
        self._username = value

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        if not isinstance(value, str):
            raise TypeError("password must be a string")
        self._password = value


__all__ = [
    "LDAPAuthProvider",
    "LDAPAuthPackage"
]
