import pytest
from lowball_ad_auth_provider import ADAuthProvider, ADAuthPackage
from lowball_ad_auth_provider.auth_provider import Server, Connection, Tls, NTLM
import lowball_ad_auth_provider
from unittest.mock import Mock, PropertyMock
import json

@pytest.fixture
def basic_ad_auth_provider():

    authp = ADAuthProvider(hostname="required", base_dn="required", domain="required")

    return authp

@pytest.fixture
def ad_auth_provider_with_service_account(basic_ad_auth_provider):

    basic_ad_auth_provider.service_account = "service_account"
    basic_ad_auth_provider.service_account_password = "password"
    return basic_ad_auth_provider

@pytest.fixture
def basic_mock_ldap3_server(monkeypatch):

    monkeypatch.setattr(Server, "__init__", Mock(return_value=None))

@pytest.fixture
def basic_mock_ldap3_server_equal(monkeypatch, basic_mock_ldap3_tls_equal):

    def mock_server_eq(self, other):

        return isinstance(other, self.__class__) and \
               other.host == self.host and \
               other.ssl == self.ssl and \
               other.tls == self.tls

    monkeypatch.setattr(Server, "__eq__", mock_server_eq)

@pytest.fixture
def basic_mock_ldap3_tls_equal(monkeypatch):

    def mock_tls_eq(self, other):
        return isinstance(other, self.__class__) and other.validate == self.validate

    monkeypatch.setattr(Tls, "__eq__", mock_tls_eq)

@pytest.fixture(params=[
    0,
    1,
    2,
    3,
    4,
    5,
    6
])
def role_mappings_groups_roles_expected_output(request):

    round = request.param

    mappings = {}
    user_groups = []
    expected_roles = []

    if round == 0:

        mappings = {}
        user_groups = ["group1", "group2"]
        expected_roles = []
    if round == 1:
        mappings = {"role1": ["group1", "Group2"]}
        user_groups = ["group2"]
        expected_roles = ["role1"]
    if round == 2:
        mappings = {"role1": ["group1"], "role2": ["group2", "GROUP1"], "role3": ["group3"]}
        user_groups = ["group1", "group2"]
        expected_roles = ["role1", "role2"]
    if round == 3:
        mappings = {"role1": ["group1", "GROUP3"], "role2": ["group2", "GROUP1"], "role3": ["group3"]}
        user_groups = ["grOup3"]
        expected_roles = ["role1", "role3"]
    if round == 4:
        mappings = {"role1": ["group1", "GROUP3"], "role2": ["group2", "GROUP1"], "role3": ["group3"]}
        user_groups = []
        expected_roles = []
    if round == 5:
        mappings = {"role1": ["group1", "GROUP3"], "role2": ["group2", "GROUP1"], "role3": ["group3"]}
        user_groups = ["group4", "group6"]
        expected_roles = []
    if round == 6:
        mappings = {"role1": ["group4", "GROUP3"], "role2": ["group2", "GROUP1"], "role3": ["group1"]}
        user_groups = ["group4", "group3"]
        expected_roles = ["role1"]

    return mappings, user_groups, expected_roles


@pytest.fixture(params=[
    "hello/",
    "hello\"",
    "hello[",
    "hello]",
    "hello:",
    "hello;",
    "hello|",
    "hello=",
    "hello,",
    "hello+",
    "hello*",
    "hello?",
    "hello>",
    "hello<"
])
def invalid_samaccountnames(request):
    return request.param


@pytest.fixture
def auth_packages_invalid_samaccount_name(invalid_samaccountnames):

    authpackage = ADAuthPackage(username=invalid_samaccountnames, password="doesntmatter")
    return authpackage



@pytest.fixture
def mock_connection_init(monkeypatch):

    monkeypatch.setattr(lowball_ad_auth_provider.auth_provider.Connection, "__init__", Mock(return_value=None))
    monkeypatch.setattr(lowball_ad_auth_provider.auth_provider.Connection, "unbind", Mock())

@pytest.fixture
def mock_connection_bind_fails(monkeypatch, mock_connection_init):

    monkeypatch.setattr(lowball_ad_auth_provider.auth_provider.Connection, "bind", Mock(return_value=False))


@pytest.fixture
def mock_connection_bind_succeeds(monkeypatch, mock_connection_init):

    monkeypatch.setattr(lowball_ad_auth_provider.auth_provider.Connection, "bind", Mock(return_value=True))


@pytest.fixture
def mock_connection_search_fails(mock_connection_bind_succeeds, monkeypatch):

    monkeypatch.setattr(lowball_ad_auth_provider.auth_provider.Connection, "search", Mock(return_value=False))


@pytest.fixture(params=[
    {
        "entries": [
            {
                "attributes": {
                    "memberOf": [
                        "group1",
                        "group2"
                    ]
                }
            }
        ]
    },
    {
        "entries": [
            {
                "attributes": {
                    "memberOf": [
                        "group3",
                        "group2"
                    ]
                }
            }
        ]
    },
    {
        "entries": [
            {
                "attributes": {
                    "memberOf": [
                        "group4",
                        "group1"
                    ]
                }
            }
        ]
    }
])
def mock_connection_search_returns_results(mock_connection_bind_succeeds, monkeypatch, request, ad_auth_provider_with_service_account):
    monkeypatch.setattr(lowball_ad_auth_provider.auth_provider.Connection, "search", Mock(return_value=True))
    monkeypatch.setattr(lowball_ad_auth_provider.auth_provider.Connection, "response_to_json", Mock(return_value=json.dumps(request.param)))
    ad_auth_provider_with_service_account.role_mappings = {
        "role1": ["group1"],
        "role2": ["group2", 'group3'],
        "role3": ["group4"]
    }
    user_groups = request.param["entries"][0]["attributes"]["memberOf"]

    expected_roles = ad_auth_provider_with_service_account.get_roles(user_groups)

    return expected_roles

@pytest.fixture
def simple_auth_package():

    return ADAuthPackage("any-client", "password")