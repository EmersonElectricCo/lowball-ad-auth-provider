.. lowball-ldap documentation master file, created by


Welcome to lowball-ad's documentation!
========================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

Installation
************

lowball-ad has been tested to work with only Python 3.6+

Pip
***

.. code-block:: bash

    pip install lowball-ad

From Source
***********

.. code-block:: bash

    git clone https://github.com/EmersonElectricCo/lowball-ad-auth-provider
    cd ./lowball-ad-auth-provider
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


**Optional Config Fields**

`roll_mappings`
  something



**Example Config**

.. code-block:: yaml

    auth_provider:
      service_account: admin
      service_account_password: myComplexPassword
      base_dn: "dc=example, dc=org"
      domain: corp
      role_mappings:
        -user : ["accounting","hr","engineering","owners"]
        -finance : ["accounting","owners"
