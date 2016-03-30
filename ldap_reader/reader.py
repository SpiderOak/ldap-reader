''' reader.py

Pulls the enterprise user groups from the LDAP server.

(c) 2016, SpiderOak, Inc.
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, you can obtain one at http://mozilla.org/MPL/2.0/ .

Function _PagedAsyncSearch() contains code as part of the
google-apps-for-your-domain-ldap-sync project
(https://code.google.com/p/google-apps-for-your-domain-ldap-sync/).
That code (c) 2006 Google, Inc.

Function _PagedAsyncSearch() *also* contains code from the
OpenStack project.
See https://git.openstack.org/cgit/openstack/keystone/commit/?id=db291b340e63b74d8d240abfc37d03fb163f33f1
That code (c) 2012 The OpenStack Foundation.

'''

from __future__ import print_function
import ldap
import logging
import re

import vendor


try:
    from ldap.controls import SimplePagedResultsControl
except ImportError:
    print("Client LDAP does not support paged results")

# MS ActiveDirectory does not properly give redirections; it passes
# redirects to the LDAP library, which dutifully follows them, but
# MSAD does not pass credentials along with the redirect process. This
# results in a case where we are using the same established, bound
# connection with our actual bound credentials having been
# stripped. The only recourse is to ignore referrals from LDAP
# servers.
ldap.set_option(ldap.OPT_REFERRALS, 0)

# Maximum number of results we're going to try to get on a single query.
_PAGE_SIZE = 900

# Are we going to use paged queries?
_TRY_PAGED_QUERIES = True


class InvalidGroupConfiguration(Exception):
    '''
    Thrown when invalid group configuration is used.
    '''
    pass


class TooManyLdapResults(Exception):
    '''
    Thrown when we get too many LDAP results.
    '''
    pass


class NotEnoughLdapResults(Exception):
    '''
    Thrown when we don't get enough LDAP results.
    '''
    pass


class LdapConnection(object):
    '''
    Represents a connection to an LDAP Server.
    '''

    def __init__(self, uri, base_dn, username, password):
        log = logging.getLogger('LdapConnection __init__')
        self.conn = ldap.initialize(uri)
        self.conn.simple_bind_s(username, password)
        log.debug("Bound to %s as %s", uri, username)
        self.conn.protocol_version = 3

        self.base_dn = base_dn

    def get_group(self, config, ldap_id):
        '''
        Returns an 'LdapGroupGroup' or 'LdapGroup' given an ldap_id.
        Arguments:
        config : dict
        ldap_id : string, group/ou distinguishedName
        '''
        group_type = self._determine_group_type(ldap_id)
        if group_type == 'ou':
            return LdapOuGroup(self, config, ldap_id)
        elif group_type == 'group':
            return LdapGroupGroup(self, config, ldap_id)

    def _determine_group_type(self, ldap_id):
        '''
        Determines if the group we're dealing with
        is either an OU or an LDAP group.
        '''

        results = self.conn.search_s(
            ldap_id,
            ldap.SCOPE_BASE,
            attrlist=['objectClass'])

        # The following are objectTypes for OUs.
        # Possibly multiple entries come back for objectClass:
        for obj_class in results[0][1]['objectClass']:
            if obj_class.lower() in LdapGroup.ou_object_classes:
                return 'ou'

        return 'group'


class LdapGroup(object):
    '''
    Abstract class to represent an LDAP Group/OU.
    '''
    ou_object_classes = set(['container', 'organizationalunit'])

    def __init__(self, ldap_conn, config, ldap_id):
        self.ldap_conn = ldap_conn
        self.ldap_id = ldap_id
        self.config = config

        # Locally cached list of users.
        self._users = None

    def _create_attrlist(self):
        """
        Creates an LDAP search attribute list based on our configuration.
        """

        attrlist = [self.config['dir_username_source'].encode('utf-8'),
                    self.config['dir_fname_source'].encode('utf-8'),
                    self.config['dir_lname_source'].encode('utf-8'),
                    ]

        if self.config.get('dir_email_source', None) not in (None, '',):
            attrlist.append(self.config['dir_email_source'].encode('utf-8'))

        attrlist.extend(vendor.enabled_attrs(self.config))

        return attrlist

    def _build_user_dict(self, result_dict):
        """
        Creates a dictionary to append to the user results list, with
        arrangement based on configuration.

        """

        user = {
            'firstname':
            result_dict.get(self.config['dir_fname_source'], [' '])[0],
            'lastname':
            result_dict.get(self.config['dir_lname_source'], [' '])[0],
        }

        if self.config.get('dir_email_source', None) not in (None, '',):
            user['email'] = result_dict[self.config['dir_email_source']][0]
            user['username'] = result_dict[
                self.config['dir_username_source']][0]
        else:
            user['email'] = result_dict[self.config['dir_username_source']][0]

        enabled_attrs_dict = {
            k: result_dict[k][0] if k in result_dict else ''
            for k in vendor.enabled_attrs(self.config)
        }
        user['enabled'] = vendor.check_enabled(
            self.config,
            enabled_attrs_dict)

        return user

    def _user_for_uid(self, uid, uid_field):
        """
        Given a UID, look up a user.
        """

        log = logging.getLogger("_user_for_uid")
        results = self.ldap_conn.conn.search_s(
            base=self.config['dir_base_dn'],
            scope=ldap.SCOPE_SUBTREE,
            filterstr="(%s=%s)" % (uid_field, uid,),
            attrlist=self._create_attrlist())

        try:
            _, result = _filter_ldap_results(results)
        except NotEnoughLdapResults:
            log.warn("No results for uid %s", uid)
            return None
        except TooManyLdapResults:
            log.warn("Multiple results for uid %s", uid)
            return None

        return result

    def _user_for_dn(self, uid):
        """
        Given a DN, look up a user.
        """

        user = self.ldap_conn.conn.search_s(
            uid,
            ldap.SCOPE_BASE,
            attrlist=self._create_attrlist())

        dist_name, user_dict = user[0]

        if dist_name is None:
            return None

        return user_dict

    def _build_user_details(self, uid, uid_field=None):
        '''
        Gathers details from the user from LDAP, and creates a user dictionary
        out of that.

        LDAP search is abstracted out based on the uid_field passed
        in. A value of None means we have a proper DN to search
        against, otherwise it represents a username field we need to
        search for.

        '''
        log = logging.getLogger('_build_user_details')
        if uid_field not in (None, ''):
            user_dict = self._user_for_uid(uid, uid_field)
        else:
            user_dict = self._user_for_dn(uid)

        if user_dict is None:
            return None

        log.debug("Appending user %s", user_dict)

        return self._build_user_dict(user_dict)

    def __iter__(self):
        """
        Provides an iterable over the user list.
        """
        if self._users is None:
            # userlist() is a virtual method for this base class, so we
            # disable pylint complaints on userlist not existing.
            self._users = self.userlist()  # pylint: disable=E1101

        for user in self._users:
            yield user


class LdapOuGroup(LdapGroup):
    '''
    Represents an LDAP OU.
    '''

    def __init__(self, ldap_conn, config, ldap_id):
        super(LdapOuGroup, self).__init__(ldap_conn, config, ldap_id)

    def userlist(self):
        '''
        Returns the list of users (user dicts) that belong
        to this LDAP OrganizationalUnit.
        '''
        log = logging.getLogger('_get_group_ou %s' % (self.ldap_id,))

        paged_async_search = _PagedAsyncSearch(
            self.ldap_conn,
            sizelimit=200000,
            base_dn=self.ldap_id,
            scope=ldap.SCOPE_SUBTREE,
            filterstr='(|'
                      '(objectClass=person)'
                      '(objectClass=user)'
                      '(objectClass=organizationalUser))',
            attrlist=self._create_attrlist())

        user_list = []
        for dist_name, result_dict in paged_async_search:
            if dist_name is None or not result_dict:
                continue
            if self.config['dir_username_source'] not in result_dict:
                log.info("User %s lacks %s, skipping", dist_name,
                         self.config['dir_username_source'])
                continue

            log.debug(
                "Appending user %s", result_dict[
                    self.config['dir_username_source']][0])

            user = self._build_user_dict(result_dict)
            user_list.append(user)

        return user_list


class LdapGroupGroup(LdapGroup):
    '''
    Represents an LDAP Group.
    '''

    def __init__(self, ldap_conn, config, ldap_id):
        super(LdapGroupGroup, self).__init__(ldap_conn, config, ldap_id)

    def _check_result_keys_for_range(self, keys):
        '''
        Check for a ranged result key. Scan the list of result keys
        and match against a regex because MSAD
        will give us results like this.
        See https://msdn.microsoft.com/en-us/library/cc223242.aspx.
        '''
        range_regex = re.compile(r"^([^;]+);range=(\d+)-(\d+|\*)$")
        result_key = self.config['dir_member_source']
        end_range = None
        for key in keys:
            match = range_regex.match(key)
            if match is not None:
                result_key = key
                if match.group(3) != '*':
                    end_range = int(match.group(3))
                else:
                    end_range = None
                break

        return (result_key, end_range,)

    def _pas_ranged_results_wrapper(self, group_ldap_id, startrange=None):
        '''
        Recursive function that wraps PagedAsyncSearch for ranged
        results from our friends, Microsoft.
        See https://github.com/SpiderOak/netkes/issues/32.
        Arguments:
        group_ldap_id: string, a group DN.
        Returns a list of child DNs.
        '''
        if startrange is None:
            attrstring = self.config['dir_member_source']
        else:
            attrstring = "%s;range=%d-*" % \
                         (self.config['dir_member_source'], startrange,)

        # We expect one and only one result here.
        results = _PagedAsyncSearch(self.ldap_conn,
                                    sizelimit=200000,
                                    base_dn=group_ldap_id,
                                    scope=ldap.SCOPE_BASE,
                                    attrlist=[attrstring])

        try:
            _, result = _filter_ldap_results(results)
        except TooManyLdapResults:
            raise Exception("Multiple results for a single unique DN?")
        except NotEnoughLdapResults:
            return []

        result_dict = result
        if not result_dict:
            return []

        result_key, end_range = self._check_result_keys_for_range(
            result_dict.keys())
        users = result_dict[result_key]
        if end_range is None:
            return users

        users.extend(
            self._pas_ranged_results_wrapper(
                group_ldap_id,
                end_range + 1))
        return users

    def _check_user(self, ldap_id):
        '''
        Checks if the ldap_id entry is a user.
        Arguments:
        ldap_id : string, entry's dn
        Returns True if the entry is a user, False otherwise
        (e.g. False for a group)
        '''
        user = self.ldap_conn.conn.search_s(
            ldap_id,
            ldap.SCOPE_BASE,
            filterstr='(|'
                      '(objectClass=account)'
                      '(objectClass=person)'
                      '(objectClass=user)'
                      '(objectClass=organizationalUser)'
                      ')',
            attrlist=[])

        return len(user) > 0

    # Maximum group depth to search for users within nested groups
    _MAX_GROUP_DEPTH = 10

    def _get_nested_users(self, ldap_id, depth=0):
        '''
        Recursive function to get the list of all
        nested users within this LDAP group.
        It also processes child groups within this group, via recursion.
        This method does not work for 'posixGroups' on OpenLDAP.
            - For AD and OpenLDAP Groups, 'member' attribute is used.
            - For RHDS Groups, 'uniqueMember' attribute is used.
        Arguments:
        ldap_id : string, entry's dn.
        Returns a list of string, each string is the DN of the user.
        '''
        # Get 'member/s' attribute of ldap_id
        members = self._pas_ranged_results_wrapper(ldap_id)

        # Check if 'ldap_id' is a user
        if not members and self._check_user(ldap_id):
            return [ldap_id]

        if depth >= self._MAX_GROUP_DEPTH:
            return []

        # It's a group, therefore we need to traverse its members
        users = []
        for member in members:
            sub_members = self._get_nested_users(member, depth + 1)
            users.extend(sub_members)

        return users

    def userlist(self):
        '''
        Returns the list of users (user dicts) that belong to this Group.
        '''
        log = logging.getLogger('_get_group_group %s' % (self.ldap_id,))
        user_list = []
        users = self._get_nested_users(self.ldap_id)
        uid_source = self.config.get('dir_uid_source', None)
        for user in users:
            log.debug("Found user %s", user)

            user_details = self._build_user_details(user, uid_source)

            if user_details is None:
                continue

            # Add each user that matches
            if not user_details['firstname'] and not user_details['lastname']:
                msg = 'Unable to process user %s. ' \
                      'The user had no first name or last name.' % user_details
                print(msg)
                log.error(msg)
            elif user_details is not None:
                user_list.append(user_details)

        return user_list


def _filter_ldap_results(results):
    '''
    Checks LDAP results for too many or too little results.
    '''

    # Make sure there's something there to begin with.
    if len(results) < 1:
        raise NotEnoughLdapResults()

    result_list = [(dist_name, result)
                   for dist_name, result in results if dist_name is not None]

    # Having more than one result for this is not good.
    if len(result_list) > 1:
        raise TooManyLdapResults()

    return result_list[0]


def get_auth_username(config, username):
    '''
    Returns the appropriate username to authenticate against.

    Will return either the `username` argument or a
    username gotten from the LDAP.
    '''
    # If we have no configuration telling us to lookup a different username,
    # just return here.
    if (config.get('dir_auth_username') in (None, '',) and
            config.get('dir_auth_source') in (None, '',)):
        return username

    my_ldap = LdapConnection(config['dir_uri'], config['dir_base_dn'],
                             config['dir_user'], config['dir_password'])

    if config.get('dir_auth_source') == 'dn':
        results = my_ldap.conn.search_s(my_ldap.base_dn,
                                        filterstr='(%s=%s)' %
                                        (config['dir_username_source'],
                                         username,),
                                        scope=ldap.SCOPE_SUBTREE,)
    else:
        results = my_ldap.conn.search_s(my_ldap.base_dn,
                                        filterstr='(%s=%s)' %
                                        (config['dir_username_source'],
                                         username,),
                                        scope=ldap.SCOPE_SUBTREE,
                                        attrlist=[
                                            config['dir_auth_username'], ])

    try:
        dist_name, result = _filter_ldap_results(results)
    except NotEnoughLdapResults:
        raise Exception("No LDAP user found for username %s" % (username,))
    except TooManyLdapResults:
        raise Exception("Too many LDAP users found "
                        "via field %s for username %s" %
                        (config['dir_username_source'], username,))

    if config.get('dir_auth_source') == 'dn':
        return dist_name
    else:
        return result[config['dir_auth_username']][0]


def can_auth(config, username, password):
    '''
    Checks the ability of the given username and password to connect to the AD.
    Returns true if valid, false if not.
    '''
    log = logging.getLogger("can_auth")
    # Throw out empty passwords.
    if password == "":
        return False

    conn = ldap.initialize(config['dir_uri'])
    try:
        auth_user = get_auth_username(config, username)
        conn.simple_bind_s(auth_user, password)
    # ANY failure here results in a failure to auth. No exceptions!
    except Exception:
        log.debug("Failed on LDAP bind")
        return False

    return True


def collect_groups(conn, config):
    '''
    Returns a list of lists of users per user group.
    The user groups are a list of LDAP DNs.
    '''

    result_groups = []

    for group in config['groups']:
        # Make sure we don't try to sync non-LDAP groups.
        if group['user_source'] != 'ldap':
            continue
        ldap_group = conn.get_group(config, group['ldap_id'])
        result_groups.extend(ldap_group)

    return result_groups


def _PagedAsyncSearch(ldap_conn, sizelimit, base_dn, scope,
                      filterstr='(objectClass=*)', attrlist=None):
    """ Helper function that implements a paged LDAP search for
    the Search method below.
    Args:
    ldap_conn: our OMLdapConnection object
    sizelimit: max # of users to return.
    filterstr: LDAP filter to apply to the search
    attrlist: list of attributes to return.  If null, all attributes
        are returned
    Returns:
      A list of users as returned by the LDAP search
    """

    # Time to autodetect our library's API, because python-ldap's API intoduced
    # breaking changes between versions 2.3 and 2.4.
    use_old_paging_api = False

    if hasattr(ldap, 'LDAP_CONTROL_PAGE_OID'):
        use_old_paging_api = True
        paged_results_control = SimplePagedResultsControl(
            controlType=ldap.LDAP_CONTROL_PAGE_OID,
            criticality=True,
            controlValue=(_PAGE_SIZE, '')
        )
        page_ctrl_oid = ldap.LDAP_CONTROL_PAGE_OID
    else:
        paged_results_control = SimplePagedResultsControl(
            criticality=True,
            size=_PAGE_SIZE,
            cookie=''
        )
        page_ctrl_oid = ldap.controls.SimplePagedResultsControl.controlType

    logging.debug('Paged search on %s for %s', base_dn, filterstr)
    users = []
    ix = 0

    while True:
        if _PAGE_SIZE == 0:
            serverctrls = []
        else:
            serverctrls = [paged_results_control]
        msgid = ldap_conn.conn.search_ext(base_dn, scope,
                                          filterstr, attrlist=attrlist, serverctrls=serverctrls)
        res = ldap_conn.conn.result3(msgid=msgid)
        unused_code, results, unused_msgid, serverctrls = res
        for result in results:
            ix += 1
            users.append(result)
            if sizelimit and ix >= sizelimit:
                break
        if sizelimit and ix >= sizelimit:
            break
        cookie = None
        for serverctrl in serverctrls:
            if serverctrl.controlType == page_ctrl_oid:
                if use_old_paging_api:
                    unused_est, cookie = serverctrl.controlValue
                    if cookie:
                        paged_results_control.controlValue = (
                            _PAGE_SIZE, cookie)
                else:
                    cookie = paged_results_control.cookie = serverctrl.cookie
                break

        if not cookie:
            break
    return users
