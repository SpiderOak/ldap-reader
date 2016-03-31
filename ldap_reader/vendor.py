''' vendor.py
Module with logic for each LDAP Vendor.
Supported vendors/servers:
    - Microsoft Active Directory (AD)
    - Red Hat Directory Server (RHDS)
    - OpenLDAP
'''

import uuid

# AD 'userAccountControl' attribute flag values
AD_ACCOUNT_DISABLE = 0x0002
AD_LOCKOUT = 0x0010
AD_PASSWORD_EXPIRED = 0x800000


def _check_enabled_ad(attrs_dict):
    '''
    Checks 'userAccountControl' attribute,
    https://support.microsoft.com/en-us/kb/305144.
    The following bits are checked, if one of them is enabled,
    then we consider the user as disabled:
        - ACCOUNTDISABLE bit 0x0002
        - LOCKOUT bit 0x0010
        - PASSWORD_EXPIRED bit 0x00800000
    '''
    try:
        user_account_control_str = attrs_dict['userAccountControl']
        if not user_account_control_str:
            return True
        user_account_control = int(user_account_control_str)
    except KeyError:
        # if not present, then we consider the account enabled
        return True
    user_disabled = bool(user_account_control & AD_ACCOUNT_DISABLE) or \
        bool(user_account_control & AD_LOCKOUT) or \
        bool(user_account_control & AD_PASSWORD_EXPIRED)
    return not user_disabled


def _check_enabled_open_ldap(attrs_dict):
    '''
    Checks 'PwdAccountLockedTime' attribute,
    http://ldapwiki.willeke.com/wiki/PwdAccountLockedTime.
    "PwdAccountLockedTime is used to indicate
    the account is Administratively Disabled".
    TODO: More research is needed.
    '''
    enabled = True
    try:
        pwd_account_locked_time = attrs_dict['pwdAccountLockedTime']
        enabled = pwd_account_locked_time in (None, '',)
    except KeyError:
        pass
    return enabled


def _check_enabled_rhds(attrs_dict):
    '''
    Checks 'nsAccountLock' attribute.
    https://access.redhat.com/documentation/en-US/
    Red_Hat_Directory_Server/8.2/html/Administration_Guide/
    User_Account_Management-Inactivating_Users_and_Roles.html
    Returns False if 'nsAccountLock' is set to 'TRUE'.
    '''
    enabled = True
    try:
        ns_account_lock = attrs_dict['nsAccountLock']
        enabled = ns_account_lock.lower() != "true"
    except KeyError:
        # if not present, then account is enabled
        pass
    return enabled

_SERVER_ENABLE_ATTR_MAP = {
    'AD': (['userAccountControl'], _check_enabled_ad),
    'RHDS': (['nsAccountLock'], _check_enabled_rhds),
    'OpenLDAP': (['pwdAccountLockedTime'], _check_enabled_open_ldap),
}


def enabled_attrs(config):
    '''
    Return a list of LDAP fields determining user enable/disable status.

    Each type of LDAP has its own means of tracking if a user is enabled
    or disabled. This function will return a list of the appropriate fields
    for the type of LDAP we are using.
    '''
    server_type = config['server_type']
    return _SERVER_ENABLE_ATTR_MAP[server_type][0]


def check_enabled(config, attrs_dict):
    '''
    Return boolean value of an enabled account
    based on the attributes given.

    We expect attrs_dict to be a dictionary with
    keys corresponding to the return value of `enabled_attrs()`.
    Based on per-implementation rules, we will return True or False
    if an account is active or inactive.
    '''
    server_type = config["server_type"]
    return _SERVER_ENABLE_ATTR_MAP[server_type][1](attrs_dict)


def fix_guid(config, guid):
    '''
    Ensures GUIDs are properly encoded if they're from AD.
    AD uses 'Octet String' for 'objectGUID' type.
    '''
    if guid and config['server_type'] == 'AD':
        return str(uuid.UUID(bytes_le=guid))
    else:
        return guid
