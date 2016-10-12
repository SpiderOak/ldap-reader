#! /usr/bin/env python
''' test_reader.py
Unit Tests for the ldap_reader module
'''

import unittest
from mock import patch, Mock, MagicMock, sentinel

from ldap_reader import reader, vendor


class TestLdapConnection(unittest.TestCase):

    @patch('ldap.initialize')
    def test_connection_creation(self, ldap_mod):
        con = reader.LdapConnection('aaa', 'bbb', 'ccc', 'ddd', [])

        self.assertEqual(con.base_dn, 'bbb')

    @patch('ldap.initialize')
    def test_connection_failure(self, ldap_mod):
        ldap_mod.side_effect = Exception('broken connection')

        with self.assertRaises(Exception):
            reader.LdapConnection('aaa', 'bbb', 'ccc', 'ddd', [])

    @patch('ldap.initialize')
    def test_auth_failure(self, ldap_mod):
        mockcon = Mock()
        mockcon.simple_bind_s.side_effect = Exception('bad credentials')

        ldap_mod.return_value = mockcon

        with self.assertRaises(Exception):
            reader.LdapConnection('aaa', 'bbb', 'ccc', 'ddd', [])

    @patch('ldap_reader.reader.LdapGroupGroup')
    @patch('ldap_reader.reader.LdapOuGroup')
    @patch('ldap_reader.reader.LdapConnection._determine_group_type')
    @patch('ldap.initialize')
    def test_get_group_correct_type_for_ou(
            self, ldap_mod, d_grp_typ, l_ou_grp, l_grp_grp):
        d_grp_typ.return_value = "ou"

        l_ou_grp.return_value = sentinel.ougrp
        l_grp_grp.return_value = sentinel.grpgrp

        con = reader.LdapConnection('aaa', 'bbb', 'ccc', 'ddd', [])
        ougrp = con.get_group('aaa')

        self.assertIs(ougrp, sentinel.ougrp)

    @patch('ldap_reader.reader.LdapGroupGroup')
    @patch('ldap_reader.reader.LdapOuGroup')
    @patch('ldap_reader.reader.LdapConnection._determine_group_type')
    @patch('ldap.initialize')
    def test_get_group_correct_type_for_group(
            self, ldap_mod, d_grp_typ, l_ou_grp, l_grp_grp):
        d_grp_typ.return_value = "group"

        l_ou_grp.return_value = sentinel.ougrp
        l_grp_grp.return_value = sentinel.grpgrp

        con = reader.LdapConnection('aaa', 'bbb', 'ccc', 'ddd', [])
        grpgrp = con.get_group('aaa')

        self.assertIs(grpgrp, sentinel.grpgrp)


class TestLdapOuGroup(unittest.TestCase):

    def setUp(self):
        self.config = {
            'server_type': 'AD',
            'dir_username_source': 'userPrincipalName',
            'dir_fname_source': 'givenName',
            'dir_lname_source': 'sn',
            'dir_guid_source': 'objectGUID',
        }

        self.ldap_results = [
            ('CN=Test1,CN=users,DC=test,DC=local',
             {'userPrincipalName': ['Test1@test.local'],
              'givenName': ['Billy'],
              'sn': ['Tester'],
              }),
            ('CN=Test2,CN=users,DC=test,DC=local',
             {'userPrincipalName': ['Test2@test.local'],
              'givenName': ['Dead'],
              'sn': ['Beef'],
              }),
            ('CN=Fawlty,CN=users,DC=test,DC=local',
             {}),
            ('CN=Robot,CN=users,DC=test,DC=local',
             {'userPrincipalName': ['robot@test.local']}),
        ]

        self.group_results = [
            {'email': 'Test1@test.local',
             'firstname': 'Billy',
             'lastname': 'Tester',
             'enabled': True,
             },
            {'email': 'Test2@test.local',
             'firstname': 'Dead',
             'lastname': 'Beef',
             'enabled': True,
             },
            {'email': 'robot@test.local',
             'firstname': ' ',
             'lastname': ' ',
             'enabled': True,
             },
        ]

        self.group_results_no_names = [
            {
                'email': user['email'],
                'enabled': user['enabled'],
            }
            for user in self.group_results
        ]


    @patch('ldap_reader.reader._PagedAsyncSearch')
    def test_userlist(self, mock_pas):
        mock_pas.return_value = self.ldap_results

        # Mock LdapConnection.check_enabled() to return True
        mock_ldap_conn = MagicMock()
        mock_ldap_conn.check_enabled.return_value = True

        grp = reader.LdapOuGroup(
            mock_ldap_conn, self.config, sentinel.ldap_id)
        users = grp.userlist()

        self.assertEqual(self.group_results, users)

    @patch('ldap_reader.reader._PagedAsyncSearch')
    def test_userlist_raises(self, mock_pas):
        mock_pas.return_value = self.ldap_results
        mock_pas.side_effect = Exception('TestException')

        grp = reader.LdapOuGroup(
            MagicMock(), self.config, sentinel.ldap_id)

        with self.assertRaises(Exception):
            grp.userlist()

    @patch('ldap_reader.reader._PagedAsyncSearch')
    def test_userlist_no_names(self, mock_pas):
        config = {
            'server_type': self.config['server_type'],
            'dir_username_source': self.config['dir_username_source'],
            'dir_guid_source': self.config['dir_guid_source'],
        }
        mock_pas.return_value = self.ldap_results

        # Mock LdapConnection.check_enabled() to return True
        mock_ldap_conn = MagicMock()
        mock_ldap_conn.check_enabled.return_value = True

        grp = reader.LdapOuGroup(
            mock_ldap_conn, config, sentinel.ldap_id,
        )
        users = grp.userlist()

        self.assertEqual(self.group_results_no_names, users)

class TestLdapGroupGroup(unittest.TestCase):

    def setUp(self):
        self.config = {
            'server_type': 'AD',
            'dir_member_source': 'member',
            'dir_username_source': 'userPrincipalName',
            'dir_fname_source': 'givenName',
            'dir_lname_source': 'sn',
            'dir_guid_source': 'objectGUID',
        }

        self.get_nested_users_results = [
            'CN=Test1,CN=users,DC=test,DC=local',
            'CN=Test2,CN=users,DC=test,DC=local',
            'CN=Robot,CN=users,DC=test,DC=local',
        ]

        self.return_test1 = {
            'userPrincipalName': ['Test1@test.local'],
            'givenName': ['Billy'],
            'sn': ['Tester'],
            'userAccountControl': [512],
            'objectGUID':
            [b'\x78\x56\x34\x12\x34\x12\x78\x56'
             '\x12\x34\x56\x78\x12\x34\x56\x78'],
        }
        self.return_test2 = {
            'userPrincipalName': ['Test2@test.local'],
            'givenName': ['Dead'],
            'sn': ['Beef'],
            'userAccountControl': [512],
            'objectGUID':
            [b'\x56\x78\x12\x34\x12\x34\x56\x78'
             '\x34\x56\x78\x12\x34\x56\x78\x12'],
        }
        self.return_robot = {
            'userPrincipalName': ['robot@test.local']
        }

        self.group_results = [
            {'email': 'Test1@test.local',
             'firstname': 'Billy',
             'lastname': 'Tester',
             'enabled': True,
             'uniqueid': '12345678-1234-5678-1234-567812345678',
             },
            {'email': 'Test2@test.local',
             'firstname': 'Dead',
             'lastname': 'Beef',
             'enabled': True,
             'uniqueid': '34127856-3412-7856-3456-781234567812',
             },
            {'email': 'robot@test.local',
             'firstname': ' ',
             'lastname': ' ',
             'enabled': True,
             },
        ]

    @patch('ldap_reader.reader.LdapGroup._user_for_dn')
    @patch('ldap_reader.reader.LdapGroupGroup._get_nested_users')
    def test_userlist(self, mock_get_nested_users, mock_user_for_dn):
        '''
        Generic test case for LdapGroupGroup.userlist().
        '''
        mock_get_nested_users.return_value = self.get_nested_users_results
        mock_user_for_dn.side_effect = [
            self.return_test1,
            self.return_test2,
            self.return_robot]
        mock_ldap_conn = MagicMock()
        mock_ldap_conn.check_enabled.return_value = True
        group = reader.LdapGroupGroup(
            mock_ldap_conn, self.config, sentinel.ldap_id)

        self.assertEqual(group.userlist(), self.group_results)


class TestVendor(unittest.TestCase):

    def setUp(self):
        self.config_ad = {
            'server_type': 'AD',
        }

        self.config_rhds = {
            'server_type': 'RHDS',
        }

        self.config_openldap = {
            'server_type': 'OpenLDAP',
        }

    def test_enabled_attrs(self):
        '''
        Test enabled_attrs for AD, RHDS and OpenLDAP.
        '''
        self.assertEqual(
            vendor.enabled_attrs(self.config_ad),
            ['userAccountControl']
        )
        self.assertEqual(
            vendor.enabled_attrs(self.config_rhds),
            ['nsAccountLock']
        )
        self.assertEqual(
            vendor.enabled_attrs(self.config_openldap),
            ['pwdAccountLockedTime']
        )

    def test_check_enabled(self):
        '''
        Test check_enabled for AD, RHDS and OpenLDAP.
        '''
        # AD
        self.assertEqual(
            vendor.check_enabled(self.config_ad, {
                'userAccountControl': 0x100  # Normal Account
            }),
            True)
        self.assertEqual(
            vendor.check_enabled(self.config_ad, {
                'userAccountControl': 0x102  # Disabled Account
            }),
            False)
        self.assertEqual(
            vendor.check_enabled(self.config_ad, {
                'userAccountControl': 0x110  # Locked Account
            }),
            False)

        # RHDS
        self.assertEqual(
            vendor.check_enabled(self.config_rhds, {
                'nsAccountLock': 'true',
            }),
            False)
        self.assertEqual(vendor.check_enabled(self.config_rhds, {}), True)

        # OpenLDAP
        self.assertEqual(vendor.check_enabled(self.config_openldap, {}), True)
        self.assertEqual(
            vendor.check_enabled(self.config_openldap, {
                'pwdAccountLockedTime': '20320101000000Z',
            }),
            False)


if __name__ == "__main__":
    unittest.main()
