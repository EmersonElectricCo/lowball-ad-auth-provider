from lowball.models.provider_models.auth_provider import AuthProvider, AuthPackage
from lowball.models.authentication_models import ClientData
from lowball.exceptions import AuthenticationNotInitializedException, InvalidCredentialsException

import ssl
import json
from ldap3 import Server, Connection, NTLM, ALL_ATTRIBUTES, Tls


class ADAuthProvider(AuthProvider):
    """Default Auth Provider for Lowball Applications
    This is the primary class for the lowball-ldap Authentication Provider.
    :param username: the username of service account able to lookup and validate users.
    :type username: str
    :param password: the password of the service account.
    :type password: str
    """

    def __init__(self,
                 hostname,
                 base_dn,
                 domain,
                 ignore_ssl_cert_errors=False,
                 role_mappings={}
                 ):

        super(ADAuthProvider, self).__init__()

        # Validate All Args
        if not isinstance(hostname, str):
            raise TypeError("hostname must be a string")
        self._hostname = hostname

        if not isinstance(base_dn, str):
            raise TypeError("base_dn must be a string")
        self._base_dn = base_dn

        if not isinstance(domain, str):
            raise TypeError("domain must be a string")
        self._domain = domain

        if ignore_ssl_cert_errors:
            tls_configuration = Tls(validate=ssl.CERT_NONE)
            self._server = Server(hostname, use_ssl=True, tls=tls_configuration)
        else:
            self._server = Server(hostname, use_ssl=True)

        if not isinstance(role_mappings, dict) or not all(isinstance(value, list) for value in role_mappings.values()):
            raise TypeError("role_mappings must be of type dict with arrays of strings")
        self._role_mappings = role_mappings

    def authenticate(self, auth_package):
        """Authenticate a user.
        something something
        :param auth_package: data needed to authenticate with this provider
        :type auth_package: ADAuthPackage
        :return: auth data
        :rtype: AuthData
        """
        conn = Connection(self._server,
                          user=auth_package.username,
                          password=auth_package.password,
                          authentication=NTLM)

        if conn.bind():
            if conn.search(self._base_dn, '(sAMAccountName=' + auth_package.username + ')', attributes=ALL_ATTRIBUTES):
                user_data = json.loads(conn.response_to_json())
                roles = []
                for group in user_data['memberOf']:
                    for role in self._role_mappings:
                        if group in self._role_mappings[role]:
                            roles.append(role)
                unique_roles = set(roles)

                return ClientData(client_id=auth_package.username, roles=list(unique_roles))

            else:
                raise AuthenticationNotInitializedException
        else:
            raise InvalidCredentialsException

    @property
    def auth_package_class(self):
        """The auth package class that this class' `authenticate` method accepts."""
        return ADAuthPackage


class ADAuthPackage(AuthPackage):
    def __init__(self, username, password, **kwargs):
        super(ADAuthPackage, self).__init__(**kwargs)
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
    "ADAuthProvider",
    "ADAuthPackage"
]
