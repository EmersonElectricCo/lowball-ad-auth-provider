.. lowball-ldap documentation master file, created by


Welcome to lowball-ldap's documentation!
========================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

Installation
************

lowball-ldap has been tested to work with only Python 3.6+

Pip
***

.. code-block:: bash

    pip install lowball-ldap

From Source
***********

.. code-block:: bash

    git clone https://github.com/EmersonElectricCo/lowball-ldap-auth-provider
    cd ./lowball-ldap-auth-provider
    python setup.py install

Configuration
*************

**Mandatory Config Fields**

`service_account`
  username of the service account used to lookup users.

`service_account_password`
  password of the service account

`base_dn`
  base dn of the of the search path for users

`hostname`
  hostname or ip of the server to use

`domain`
  domain to prepend in front of user authentications

`username_ldap_attribute`
  attribute to use as the username


**Optional Config Fields**

`roll_mappings`
  something

`protocol`
  `ldap` or `ldaps`. If not set, defaults to `ldap`

`port`
  port on the server to use. If no set, defaults to the appropriate port for the chosen protocol


**Example Config**

.. code-block:: yaml

    auth_provider:
      service_account: admin
      service_account_password: myComplexPassword
      base_dn: "dc=example, dc=org"
      domain: corp
      username_ldap_attribute: uid
      role_mappings:
        -user : ["accounting","hr","engineering","owners"]
        -finance : ["accounting","owners"
