from lowball.models.provider_models.auth_provider import AuthProvider, AuthPackage
from lowball.models.authentication_models import ClientData
from lowball.exceptions import AuthenticationNotInitializedException, InvalidCredentialsException, NotFoundException, \
    BadRequestException

import ssl
import json
from ldap3 import Server, Connection, NTLM, Tls

# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb726984(v=technet.10)?redirectedfrom=MSDN
INVALID_SAMACCOUNTNAME_CHARS = "\"/\\[]:;|=,+*?<>"


class ADAuthProvider(AuthProvider):
    """Default Auth Provider for Lowball Applications
    This is the primary class for the lowball_ad_auth_provider Authentication Provider.
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

        super(ADAuthProvider, self).__init__()

        self.hostname = hostname
        self.base_dn = base_dn
        self.domain = domain
        self.service_account = service_account
        self.service_account_password = service_account_password
        self.use_ssl = use_ssl
        self.ignore_ssl_cert_errors = ignore_ssl_cert_errors
        self.role_mappings = role_mappings

    @property
    def hostname(self):
        return self._hostname

    @hostname.setter
    def hostname(self, value):
        if not value or not isinstance(value, str):
            raise ValueError("hostname must be a nonempty string")
        self._hostname = value

    @property
    def base_dn(self):
        return self._base_dn

    @base_dn.setter
    def base_dn(self, value):
        if not value or not isinstance(value, str):
            raise ValueError("base_dn must be nonempty a string")
        self._base_dn = value

    @property
    def domain(self):
        return self._domain

    @domain.setter
    def domain(self, value):
        if not value or not isinstance(value, str):
            raise ValueError("domain must be nonempty a string")
        self._domain = value

    @property
    def use_ssl(self):
        return self._use_ssl

    @use_ssl.setter
    def use_ssl(self, value):
        if not isinstance(value, bool):
            raise ValueError("use_ssl must be a boolean")
        self._use_ssl = value

    @property
    def service_account(self):
        return self._service_account

    @service_account.setter
    def service_account(self, value):
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise ValueError("service_account must be a string or empty")
        self._service_account = value

    @property
    def service_account_password(self):
        return self._service_account_password

    @service_account_password.setter
    def service_account_password(self, value):
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise ValueError("service_account_password must be a string or empty")
        self._service_account_password = value

    @property
    def ignore_ssl_cert_errors(self):
        return self._ignore_ssl_cert_errors

    @ignore_ssl_cert_errors.setter
    def ignore_ssl_cert_errors(self, value):
        if not isinstance(value, bool):
            raise ValueError("ignore_ssl_cert_errors must be a boolean")
        self._ignore_ssl_cert_errors = value

    @property
    def role_mappings(self):
        return self._role_mappings

    @role_mappings.setter
    def role_mappings(self, value):
        if value is None:
            value = {}
        if not isinstance(value, dict):
            raise ValueError("Invalid role mappings. Must be a dictionary of {str: [str, str],..}")
        for key, mappings in value.items():
            if not isinstance(key, str) or not isinstance(mappings, list) or not all(isinstance(group, str) for group in mappings):
                raise ValueError("Invalid role mappings. Must be a dictionary of {str: [str, str],..}")

        self._role_mappings = value

    @property
    def auth_package_class(self):
        """The auth package class that this class' `authenticate` method accepts."""
        return ADAuthPackage

    def get_server(self):

        if self.use_ssl:
            if self.ignore_ssl_cert_errors:
                tls_configuration = Tls(validate=ssl.CERT_NONE)
                return Server(host=self.hostname, use_ssl=True, tls=tls_configuration)
            else:
                return Server(host=self.hostname, use_ssl=True)
        else:
            return Server(host=self.hostname, use_ssl=False)

    def get_roles(self, groups):

        groups = [group.lower() for group in groups]

        return [role for role, mapping in self.role_mappings.items() if any(group.lower() in [mapped_group.lower() for mapped_group in mapping] for group in groups)]

    def _validate_samaccountname(self, name):
        if any(c in name for c in INVALID_SAMACCOUNTNAME_CHARS):
            raise BadRequestException("Submitted samaccountname contained invalid characters")

    def _ad_search(self, connection, samaccountname):
        if connection.search(
                search_base=self.base_dn,
                search_filter=f'(sAMAccountName={samaccountname})',
                attributes="memberOf"):
            user_data = json.loads(connection.response_to_json())
            connection.unbind()
            user_groups = user_data['entries'][0]['attributes']['memberOf']
            roles = self.get_roles(user_groups)
            return ClientData(client_id=samaccountname, roles=roles)

        else:
            connection.unbind()
            return False

    def authenticate(self, auth_package):
        """Authenticate a user.
        :param auth_package: data needed to authenticate with this provider
        :type auth_package: ADAuthPackage
        :return: auth data
        :rtype: AuthData
        """

        self._validate_samaccountname(auth_package.username)

        conn = Connection(server=self.get_server(),
                          user=self.domain + "\\" + auth_package.username,
                          password=auth_package.password,
                          authentication=NTLM)

        # Connects with user; True if Valid Creds and Server Reachable
        if conn.bind():
            client_data = self._ad_search(conn, auth_package.username)
            if client_data:
                return client_data
            # We were able to bind but the user wasn't found. Likely a config issue with the base DN
            else:
                exception = AuthenticationNotInitializedException()
                exception.description = "Unable to locate user though authentication succeeded. Check configuration"

                raise exception
        else:
            raise InvalidCredentialsException

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
            self._validate_samaccountname(client_id)

            conn = Connection(server=self.get_server(),
                              user=self.domain + "\\" + self.service_account,
                              password=self._service_account_password,
                              authentication=NTLM)
            if conn.bind():
                client_data = self._ad_search(conn, client_id)
                if client_data:
                    return client_data
                else:
                    raise NotFoundException(f"The client_id: {client_id} was not found")
            else:

                exception = AuthenticationNotInitializedException()
                exception.description = "get_client not configured. Unable to connect to AD Server with given hostname" \
                                        " and service account"

                raise exception


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
