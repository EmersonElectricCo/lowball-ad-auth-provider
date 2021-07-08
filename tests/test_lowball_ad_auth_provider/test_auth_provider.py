import pytest
from lowball_ad_auth_provider.auth_provider import ADAuthPackage, ADAuthProvider, Server, Tls, ssl, Connection, NTLM, ClientData
from lowball.exceptions import InvalidCredentialsException, AuthenticationNotInitializedException, BadRequestException, \
    NotFoundException
from unittest.mock import Mock, PropertyMock, call

class TestADAuthPackage:
    @pytest.mark.parametrize("username,password", [
        ("username", "password"),
        ("user", "pass"),
        ("something", "something_else")
    ])
    def test_init_sets_properties_as_expected(self, username, password):

        authp = ADAuthPackage(username=username, password=password)

        assert authp.username == username
        assert authp.password == password

    @pytest.mark.parametrize("username,password", [
        ("okusername", None),
        ("okusername", ["not", "string"]),
        (None, "okpassword"),
        (["not", "string"], "okpassword")
    ])
    def test_type_error_when_invalid_inputs(self, username, password):
        with pytest.raises(TypeError):
            authp = ADAuthPackage(username=username, password=password)


class TestADAuthProvider:

    def test_init_sets_expected_defaults(self):
        authp = ADAuthProvider(hostname="required", base_dn="required", domain="required")

        assert authp.hostname == "required"
        assert authp.base_dn == "required"
        assert authp.domain == "required"
        assert authp.service_account == ""
        assert authp.service_account_password == ""
        assert authp.use_ssl
        assert not authp.ignore_ssl_cert_errors
        assert authp.role_mappings == {}

    def test_init_accepts_expected_kwargs(self):
        authp = ADAuthProvider(
            hostname="required",
            base_dn="required",
            domain="required",
            service_account="admin",
            service_account_password="adminp",
            use_ssl=False,
            ignore_ssl_cert_errors=True,
            role_mappings={"role": ["super_role1"]}
        )

        assert authp.hostname == "required"
        assert authp.base_dn == "required"
        assert authp.domain == "required"
        assert authp.service_account == "admin"
        assert authp.service_account_password == "adminp"
        assert not authp.use_ssl
        assert authp.ignore_ssl_cert_errors
        assert authp.role_mappings == {"role": ["super_role1"]}


    @pytest.mark.parametrize("hostname,valid", [
        ("validstring", True),
        ("", False),
        (None, False),
        (["not", "string"], False),
        ("another.valid.string", True)
    ])
    def test_hostname_property_requires_non_empty_string(self, hostname, valid, basic_ad_auth_provider):

        if valid:
            basic_ad_auth_provider.hostname = hostname
            assert basic_ad_auth_provider.hostname == hostname
        else:
            with pytest.raises(ValueError):
                basic_ad_auth_provider.hostname = hostname

    @pytest.mark.parametrize("base_dn,valid", [
        ("validstring", True),
        ("", False),
        (None, False),
        (["not", "string"], False),
        ("another.valid.string", True)
    ])
    def test_base_dn_property_requires_non_empty_string(self, base_dn, valid, basic_ad_auth_provider):

        if valid:
            basic_ad_auth_provider.base_dn = base_dn
            assert basic_ad_auth_provider.base_dn == base_dn
        else:
            with pytest.raises(ValueError):
                basic_ad_auth_provider.base_dn = base_dn

    @pytest.mark.parametrize("domain,valid", [
        ("validstring", True),
        ("", False),
        (None, False),
        (["not", "string"], False),
        ("another.valid.string", True)
    ])

    def test_domain_property_requires_non_empty_string(self, domain, valid, basic_ad_auth_provider):

        if valid:
            basic_ad_auth_provider.domain = domain
            assert basic_ad_auth_provider.domain == domain
        else:
            with pytest.raises(ValueError):
                basic_ad_auth_provider.domain = domain

    @pytest.mark.parametrize("value,valid,expected", [
        ("validstring", True, "validstring"),
        ("", True, ""),
        (None, True, ""),
        (["not", "string"], False, None),
        ("another.valid.string", True, "another.valid.string"),
        (1234, False, None)
    ])
    def test_service_account_property_requires_string_or_none(self, value, valid, expected, basic_ad_auth_provider):

        if valid:
            basic_ad_auth_provider.service_account = value
            assert basic_ad_auth_provider.service_account == expected
        else:
            with pytest.raises(ValueError):
                basic_ad_auth_provider.service_account = value

    @pytest.mark.parametrize("value,valid,expected", [
        ("validstring", True, "validstring"),
        ("", True, ""),
        (None, True, ""),
        (["not", "string"], False, None),
        ("another.valid.string", True, "another.valid.string"),
        (1234, False, None)
    ])
    def test_service_account_password_property_requires_string_or_none(self,  value, valid, expected, basic_ad_auth_provider):

        if valid:
            basic_ad_auth_provider.service_account_password = value
            assert basic_ad_auth_provider.service_account_password == expected
        else:
            with pytest.raises(ValueError):
                basic_ad_auth_provider.service_account_password = value

    @pytest.mark.parametrize("value,valid", [
        (True, True),
        (False, True),
        (None, False),
        (["not", "bool"], False),
        (1234, False)
    ])
    def test_use_ssl_property_requires_boolean(self, value, valid, basic_ad_auth_provider):

        if valid:
            basic_ad_auth_provider.use_ssl = value
            assert basic_ad_auth_provider.use_ssl == value
        else:
            with pytest.raises(ValueError):
                basic_ad_auth_provider.use_ssl = value

    @pytest.mark.parametrize("value,valid", [
        (True, True),
        (False, True),
        (None, False),
        (["not", "bool"], False),
        (1234, False)
    ])
    def test_ignore_ssl_cert_errors_property_requires_boolean(self, value, valid, basic_ad_auth_provider):

        if valid:
            basic_ad_auth_provider.ignore_ssl_cert_errors = value
            assert basic_ad_auth_provider.ignore_ssl_cert_errors == value
        else:
            with pytest.raises(ValueError):
                basic_ad_auth_provider.ignore_ssl_cert_errors = value

    @pytest.mark.parametrize("value,valid,expected", [
        ({}, True, {}),
        ({
            "role1": ["group1", "group2"],
            "role2": ["Group3"]
         },
         True,
         {
            "role1": ["group1", "group2"],
            "role2": ["Group3"]
         }),
        ("just_string", False, None),
        (None, True, {}),
        ({11122: ["group"]}, False, None),
        ({"role1": ["group1", 11111]}, False, None),
        ({"role1": ["something", "something1"], "role2": {"umm": "not list"}}, False, None),
        ({"role1": ["something", "something2"], "role2": ["mapping", 112323]}, False, None)

    ])
    def test_role_mappings_property_requires_dict_string_list_strings_or_none(self,  value, valid, expected, basic_ad_auth_provider):

        if valid:
            basic_ad_auth_provider.role_mappings = value
            assert basic_ad_auth_provider.role_mappings == expected
        else:
            with pytest.raises(ValueError):
                basic_ad_auth_provider.role_mappings = value

    @pytest.mark.parametrize("hostname,use_ssl,ignore_ssl_cert_errors", [
        ("hostname.name", False, False),
        ("hostname.named", True, False),
        ("hostname.nameo", True, True),
        ("hostname.namee", False, True)
    ])
    def test_get_server_method_creates_expected_server_object(self, basic_mock_ldap3_server,
                                                              hostname,
                                                              use_ssl,
                                                              ignore_ssl_cert_errors,
                                                              basic_ad_auth_provider,
                                                              basic_mock_ldap3_tls_equal):

        basic_ad_auth_provider.hostname = hostname
        basic_ad_auth_provider.use_ssl = use_ssl
        basic_ad_auth_provider.ignore_ssl_cert_errors = ignore_ssl_cert_errors

        server = basic_ad_auth_provider.get_server()

        assert isinstance(server, Server)

        if use_ssl:
            if ignore_ssl_cert_errors:
                expected_call = call(host=hostname, use_ssl=use_ssl, tls=Tls(validate=ssl.CERT_NONE))
            else:
                expected_call = call(host=hostname, use_ssl=use_ssl)

        else:
            expected_call = call(host=hostname, use_ssl=use_ssl)

        Server.__init__.assert_has_calls([expected_call])

    def test_get_roles_method_returns_expected_roles(self, basic_ad_auth_provider, role_mappings_groups_roles_expected_output):

        mappings, user_groups, expected_roles = role_mappings_groups_roles_expected_output

        basic_ad_auth_provider.role_mappings = mappings

        user_roles = basic_ad_auth_provider.get_roles(user_groups)

        assert isinstance(user_roles, list)
        assert set(user_roles) == set(expected_roles)
        assert len(user_roles) == len(expected_roles)


    def test_auth_package_class_property(self, basic_ad_auth_provider):

        authp_class = basic_ad_auth_provider.auth_package_class

        assert authp_class == ADAuthPackage


class TestADAuthProviderAuthenticate:

    # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb726984(v=technet.10)?redirectedfrom=MSDN
    # invalid characters " / \ [ ] : ; | = , + * ? < >

    USER_SEARCH = '(sAMAccountName={})'

    def test_bad_request_exception_when_user_contains_invalid_characters(self, basic_ad_auth_provider,
                                                                                 auth_packages_invalid_samaccount_name):

        with pytest.raises(BadRequestException):
            basic_ad_auth_provider.authenticate(auth_packages_invalid_samaccount_name)

    def test_invalid_credentials_exception_when_unable_to_bind(self, mock_connection_bind_fails,
                                                               ad_auth_provider_with_service_account,
                                                               simple_auth_package,
                                                               basic_mock_ldap3_server_equal):

        with pytest.raises(InvalidCredentialsException):
            ad_auth_provider_with_service_account.authenticate(simple_auth_package)

        expected_server = ad_auth_provider_with_service_account.get_server()
        expected_user_info = ad_auth_provider_with_service_account.domain + "\\" + simple_auth_package.username
        expected_password = simple_auth_package.password

        Connection.bind.assert_called_once()
        Connection.__init__.assert_called_once_with(server=expected_server,
                                                    user=expected_user_info,
                                                    password=expected_password,
                                                    authentication=NTLM)

    def test_unable_to_authenticate_exception_when_search_fails(self, ad_auth_provider_with_service_account,
                                                                simple_auth_package,
                                                                mock_connection_search_fails,
                                                                basic_mock_ldap3_server_equal):
        with pytest.raises(AuthenticationNotInitializedException):
            ad_auth_provider_with_service_account.authenticate(simple_auth_package)

        expected_server = ad_auth_provider_with_service_account.get_server()
        expected_user_info = ad_auth_provider_with_service_account.domain + "\\" + simple_auth_package.username
        expected_password = simple_auth_package.password

        Connection.bind.assert_called_once()
        Connection.__init__.assert_called_once_with(server=expected_server,
                                                    user=expected_user_info,
                                                    password=expected_password,
                                                    authentication=NTLM)
        Connection.unbind.assert_called_once()
        Connection.search.assert_called_once_with(search_base=ad_auth_provider_with_service_account.base_dn,
                                                  search_filter=self.USER_SEARCH.format("any-client"),
                                                  attributes="memberOf")

    def test_returns_client_data_with_excpected_roles_when_user_is_found(self,
                                                                         mock_connection_search_returns_results,
                                                                         ad_auth_provider_with_service_account,
                                                                         basic_mock_ldap3_server_equal,
                                                                         simple_auth_package
                                                                         ):

        expected_roles = mock_connection_search_returns_results
        expected_server = ad_auth_provider_with_service_account.get_server()
        expected_user_info = ad_auth_provider_with_service_account.domain + "\\" + simple_auth_package.username
        expected_password = simple_auth_package.password

        result = ad_auth_provider_with_service_account.authenticate(simple_auth_package)

        assert isinstance(result, ClientData)
        assert result.client_id == simple_auth_package.username
        assert set(result.roles) == set(expected_roles)

        Connection.bind.assert_called_once()
        Connection.__init__.assert_called_once_with(server=expected_server,
                                                    user=expected_user_info,
                                                    password=expected_password,
                                                    authentication=NTLM)
        Connection.response_to_json.assert_called_once()
        Connection.unbind.assert_called_once()
        Connection.search.assert_called_once_with(search_base=ad_auth_provider_with_service_account.base_dn,
                                                  search_filter=self.USER_SEARCH.format("any-client"),
                                                  attributes="memberOf")


class TestADAuthProviderGetClient:
    # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb726984(v=technet.10)?redirectedfrom=MSDN
    # invalid characters " / \ [ ] : ; | = , + * ? < >

    USER_SEARCH = '(sAMAccountName={})'

    def test_bad_request_exception_when_client_id_contains_invalid_characters_and_service_account_set(self,
                                                                                      invalid_samaccountnames,
                                                                                      ad_auth_provider_with_service_account):

        with pytest.raises(BadRequestException):
            ad_auth_provider_with_service_account.get_client(invalid_samaccountnames)

    def test_authentication_not_initialized_error_when_service_account_not_set(self, basic_ad_auth_provider):

        with pytest.raises(AuthenticationNotInitializedException):
            basic_ad_auth_provider.get_client("any-client")

    def test_authentication_not_initialized_exception_when_unable_to_bind_with_service_account(self,
                                                                                               ad_auth_provider_with_service_account,
                                                                                               mock_connection_bind_fails,
                                                                                               basic_mock_ldap3_server_equal,

                                                                                               ):
        with pytest.raises(AuthenticationNotInitializedException):
            ad_auth_provider_with_service_account.get_client("any-client")

        expected_server = ad_auth_provider_with_service_account.get_server()
        expected_user_info = ad_auth_provider_with_service_account.domain + "\\" + \
                             ad_auth_provider_with_service_account.service_account
        expected_password = ad_auth_provider_with_service_account.service_account_password

        Connection.bind.assert_called_once()
        Connection.__init__.assert_called_once_with(server=expected_server,
                                                    user=expected_user_info,
                                                    password=expected_password,
                                                    authentication=NTLM)

    def test_not_found_exception_when_no_results_returned(
            self,
            ad_auth_provider_with_service_account,
            mock_connection_search_fails,
            basic_mock_ldap3_server_equal
    ):
        with pytest.raises(NotFoundException):
            ad_auth_provider_with_service_account.get_client("any-client")

        expected_server = ad_auth_provider_with_service_account.get_server()
        expected_user_info = ad_auth_provider_with_service_account.domain + "\\" + \
                             ad_auth_provider_with_service_account.service_account
        expected_password = ad_auth_provider_with_service_account.service_account_password

        Connection.bind.assert_called_once()
        Connection.__init__.assert_called_once_with(server=expected_server,
                                                    user=expected_user_info,
                                                    password=expected_password,
                                                    authentication=NTLM)
        Connection.unbind.assert_called_once()
        Connection.search.assert_called_once_with(search_base=ad_auth_provider_with_service_account.base_dn,
                                                  search_filter=self.USER_SEARCH.format("any-client"),
                                                  attributes="memberOf")

    def test_returns_client_data_with_expected_roles_when_results_found(self,
                                                                        mock_connection_search_returns_results,
                                                                        ad_auth_provider_with_service_account,
                                                                        basic_mock_ldap3_server_equal):
        expected_roles = mock_connection_search_returns_results
        expected_server = ad_auth_provider_with_service_account.get_server()
        expected_user_info = ad_auth_provider_with_service_account.domain + "\\" + \
                             ad_auth_provider_with_service_account.service_account
        expected_password = ad_auth_provider_with_service_account.service_account_password

        result = ad_auth_provider_with_service_account.get_client("any-client")

        assert isinstance(result, ClientData)
        assert result.client_id == "any-client"
        assert set(result.roles) == set(expected_roles)

        Connection.response_to_json.assert_called_once()
        Connection.bind.assert_called_once()
        Connection.__init__.assert_called_once_with(server=expected_server,
                                                    user=expected_user_info,
                                                    password=expected_password,
                                                    authentication=NTLM)
        Connection.unbind.assert_called_once()
        Connection.search.assert_called_once_with(search_base=ad_auth_provider_with_service_account.base_dn,
                                                  search_filter=self.USER_SEARCH.format("any-client"),
                                                  attributes="memberOf")
