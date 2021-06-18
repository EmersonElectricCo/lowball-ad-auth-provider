import pytest
from lowball_ad.auth_provider import ADAuthPackage, AuthProvider

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

    def test_init_accepts_the_correct_values(self):

        pass

    def test_hostname_property_validation(self):

        pass

    def base_dn_property_validation(self):

        pass

    def test_domain_property_validation(self):

        pass

    def test_service_account_property_validation(self):

        pass

    def test_service_account_password_property_validation(self):

        pass

    def test_use_ssl_property_validation(self):

        pass

    def test_ignore_ssl_cert_errors_property_validation(self):

        pass

    def test_role_mappings_property_validation(self):

        pass

    def test_get_server_method_creates_expected_server_object(self):

        pass

    def test_get_roles_method_returns_expected_roles(self):

        pass

    def test_auth_package_class_property(self):

        pass


class TestADAuthProviderAuthenticate:

    def test_invalid_credentials_exception_when_unable_to_bind(self):

        pass

    def test_unable_to_authenticate_exception_when_search_fails(self):

        pass

    def test_returns_client_data_with_excpected_roles_when_user_is_found(self):
        pass

class TestADAuthProviderGetClient:

    def test_authentication_not_initialized_error_when_service_account_not_set(self):
        pass

    def test_not_found_exception_when_no_results_returned(self):

        pass

    def test_authentication_not_initialized_exception_when_service_account_credentials_invalid(self):
        pass

    def test_returns_none_when_no_search_results_are_found(self):

        pass

    def test_returns_client_data_with_expected_roles_when_results_found(self):

        pass
