# lowball-ad-auth-provider

lowball-ad-auth-provider is an AuthProvider implementation for a [Lowball](https://github.com/EmersonElectricCo/lowball)
microservice, that works with Active Directory.


## Installation
***

lowball-ad has been tested to work with only Python 3.6+

### Pip


```bash

    pip install lowball-ad
```

### From Source


```bash

    git clone https://github.com/EmersonElectricCo/lowball-ad-auth-provider
    cd ./lowball-ad-auth-provider
    python setup.py install
```

## Configuration
***

**Mandatory Config Fields**

`base_dn`
  base dn of the of the search path for users

`hostname`
  hostname or ip of the server to use

`domain`
  domain to prepend in front of user authentications

**Optional Config Fields**

`roll_mappings`
  a dictionary of role -> list of groups that would give a user that role

`ignore_ssl_cert_errors`
  true/false, whether or not to validate ssl. Unused if `use_ssl` is set to false

`use_ssl`
  true/false, whether or not to use ssl for the connection

`service_account`
  username of the service account used to lookup users. can be left empty, but users will not be able to look themselves
  up or create their own tokens

`service_account_password`
  password of the service account


**Example Config**

The configuration for the ad auth provider goes under the `auth_provider` section of a lowball configuration

```yaml
...
auth_provider:
  service_account: admin
  service_account_password: myComplexPassword
  base_dn: "dc=example, dc=org"
  domain: corp
  ignore_ssl_cert_errors: false
  use_ssl: true
  role_mappings:
    user:
      - CN=regular_user,OU=groups,DC=example,DC=org
      - CN=owners,OU=groups,DC=example,DC=org
    finance:
      - CN=accounting,OU=groups,DC=example,DC=org
      - CN=owners,OU=groups,DC=example,DC=org
...

```

## Example Usage
***
```python
from lowball_ad_auth_provider import ADAuthProvider
from lowball import Lowball, config_from_file

app = Lowball(config_from_file("/path/to/config"), auth_provider=ADAuthProvider)

@app.route("/hello", methods=["GET"])
def hello():
    return {"hello": "good byte"}, 200


```