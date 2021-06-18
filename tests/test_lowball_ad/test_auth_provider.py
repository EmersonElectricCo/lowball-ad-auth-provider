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
    pass

