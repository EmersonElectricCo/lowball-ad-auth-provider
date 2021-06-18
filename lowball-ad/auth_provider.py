from lowball.models.provider_models.auth_provider import AuthProvider, AuthPackage
from lowball.models.authentication_models import ClientData
from lowball.exceptions import AuthenticationNotInitializedException, InvalidCredentialsException, NotFoundException

import ssl
import json
from ldap3 import Server, Connection, NTLM, ALL_ATTRIBUTES, Tls


class RoleMappings:
    def __init__(self, mapping=None):
        if mapping is None:
            mapping = {}
        self.mapping = mapping
    @property
    def mapping(self):
        return self._mapping

    @mapping.setter
    def mapping(self, value):
        if not isinstance(value, dict):
            raise ValueError("Invalid role mappings. Must be a dictionary of {str: [str, str],..}")
        for mappings in value.values():
            if not isinstance(mappings, list) and not all(isinstance(group, str) for group in mappings):
                raise ValueError("Invalid role mappings. Must be a dictionary of {str: [str, str],..}")
        self._mapping = value

    def get_roles(self, groups):
        return [role for role, mapping in self.mapping.items() if any(group in mapping for group in groups)]


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
                 service_account="",
                 service_account_password="",
                 use_ssl=True,
                 ignore_ssl_cert_errors=False,
                 role_mappings=None
                 ):
        if role_mappings is None:
            role_mappings = {}
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
        if use_ssl:
            if ignore_ssl_cert_errors:
                tls_configuration = Tls(validate=ssl.CERT_NONE)
                self._server = Server(hostname, use_ssl=True, tls=tls_configuration)
            else:
                self._server = Server(hostname, use_ssl=True)
        else:
            self._server = Server(hostname, use_ssl=False)

        if service_account and not isinstance(service_account, str):
            raise TypeError("service_account must be a string if set")
        if service_account_password and not isinstance(service_account_password, str):
            raise TypeError("service_account_password must be a string if set")

        self._service_account = service_account
        self._service_account_password = service_account_password

        self._role_mappings = RoleMappings(role_mappings)

    def authenticate(self, auth_package):
        """Authenticate a user.
        something something
        :param auth_package: data needed to authenticate with this provider
        :type auth_package: ADAuthPackage
        :return: auth data
        :rtype: AuthData
        """
        conn = Connection(self._server,
                          user=self._domain+"\\"+auth_package.username,
                          password=auth_package.password,
                          authentication=NTLM)

        # Connects with user; True if Valid Creds and Server Reachable
        if conn.bind():
            if conn.search(self._base_dn, '(sAMAccountName=' + auth_package.username + ')', attributes=ALL_ATTRIBUTES):
                user_data = json.loads(conn.response_to_json())
                user_groups = user_data['entries'][0]['attributes']['memberOf']

                roles = self._role_mappings.get_roles(user_groups)
                conn.unbind()
                return ClientData(client_id=auth_package.username, roles=roles)

            else: # We were able to bind but the user wasnt found. Likely a config issue with the base DN
                conn.unbind()
                raise AuthenticationNotInitializedException
        else:
            raise InvalidCredentialsException

    @property
    def auth_package_class(self):
        """The auth package class that this class' `authenticate` method accepts."""
        return ADAuthPackage

    def get_client(self, client_id):
        """if service_account is configured, will enable users to create their own tokens
        The service account will need to have permissions to search for the clients

        :param client_id:
        :return:
        """
        if not self._service_account:
            exception = AuthenticationNotInitializedException()
            exception.description = "get_client not configured. Must include service_account in service configuration"
            raise exception
        else:
            conn = Connection(self._server,
                              user=self._domain + "\\" + self._service_account,
                              password=self._service_account_password,
                              authentication=NTLM)
            if conn.bind():
                if conn.search(self._base_dn, '(sAMAccountName=' + client_id + ')', attributes=ALL_ATTRIBUTES):
                    user_data = json.loads(conn.response_to_json())
                    user_groups = user_data['entries'][0]['attributes']['memberOf']
                    roles = self._role_mappings.get_roles(user_groups)
                    conn.unbind()
                    return ClientData(client_id=client_id, roles=roles)
                else:
                    conn.unbind()
                    raise NotFoundException(f"The client_id: {client_id} was not found")
            else:
                raise AuthenticationNotInitializedException


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
