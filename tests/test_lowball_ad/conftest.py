import pytest
from lowball_ad import ADAuthProvider
from lowball_ad.auth_provider import Server, Connection, Tls, NTLM
from unittest.mock import Mock, PropertyMock

@pytest.fixture
def basic_ad_auth_provider():

    authp = ADAuthProvider(hostname="required", base_dn="required", domain="required")

    return authp


@pytest.fixture
def basic_mock_ldap3_server(monkeypatch):

    monkeypatch.setattr(Server, "__init__", Mock(return_value=None))

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

