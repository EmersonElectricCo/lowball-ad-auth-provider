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
  something

`service_account_password`
  something

`base_dn`
  something

`hostname`
  something

`domain`
  something

`username_ldap_attribute`
  something


**Optional Config Fields**

`roll_mappings`
  something

`protocol`
  something

`protocol_version`
  something

`port`
  something

.. code-block:: yaml

    # service_account, r
    # service_account_password,r
    # protocol, o, ldap
    # base_dn, r
    # hostname, r
    # protocol_version, o,3
    # domain, r
    # roll_mappings, o, {}
    # username_ldap_attribute, r
    # port, o, defaults to the particular ldap protocol
