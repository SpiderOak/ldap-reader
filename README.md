# ldap-reader

Python LDAP module for listing accounts and authenticating them against LDAP servers.
It wraps `python-ldap` and provides an API that is LDAP vendor independent.

## Features

- Lists accounts within LDAP `Group`s and `OrganizationalUnit`s (OUs).
- Supports Microsoft Active Directory, Red Hat Directory Server/389 Directory Server and OpenLDAP.
- Validate account credentials.

## Usage

Print all users on a group 'MyGroup' on LDAP server for 'example.com': 

```python
import ldap_reader

config = {
    'server_type': 'AD', # Microsoft Active Directory
    'dir_username_source': 'userPrincipalName',
    'dir_member_source': 'member',
    'dir_fname_source': 'givenName',
    'dir_lname_source': 'sn',
}

# Connect to the LDAP server running on host 'myldap.example.com'
ldap_conn = ldap_reader.LdapConnection(
    'ldap://myldap.example.com:389/', 
    'dc=example,dc=com', 
    'Administrator@example.com',
    'password')

# Get Group/OU
my_group = ldap_conn.get_group(config, 'cn=MyGroup,dc=example,dc=com')

# Get the Group/OU users
users = my_group.userlist()
assert users

# Validate credentials for the first user within the group
user = users[0]
assert my_group.can_auth(user['email'], 'password')
``` 

## Configuration

Here's the specific configuration for each vendor (this pain may be avoided if auto-detection is implemented in the future)

### AD

```python
config_ad = {
    'server_type': 'AD',
    'dir_username_source': 'userPrincipalName',
    'dir_member_source': 'member',
    'dir_guid_source': 'objectGUID',
    ...
}
```

### RHDS/389DS

```python
config_rhds = {
    'server_type': 'RHDS',
    'dir_username_source': 'uid',
    'dir_member_source': 'uniqueMember',
    'dir_guid_source': 'nsuniqueid',
    ...
}
```

### OpenLDAP

```python
config_openldap = {
    'server_type': 'OpenLDAP',
    'dir_username_source': 'uid',
    'dir_member_source': 'member',
    'dir_guid_source': 'entryUUID',
    ...
}
```

## TODO

- LDAP Vendor type autodetection (this would relieve users from setting a config)
- Make `LdapGroup.userlist()` work for OpenLDAP `posixGroups`.
- More research is needed for OpenLDAP Enabled/Disabled account detection (see `ldap_reader.vendor._check_enabled_open_ldap()`).
- Unit tests for all `ldap_reader` public methods.
