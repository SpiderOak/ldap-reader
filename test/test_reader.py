import unittest
from mock import patch, Mock, MagicMock, sentinel

from ldap_reader import reader

class TestLdapConnection(unittest.TestCase):
        
    @patch('ldap.initialize')
    def test_connection_creation(self, ldapMod):
        con = reader.LdapConnection('aaa', 'bbb', 'ccc', 'ddd')

        self.assertEqual(con.base_dn, 'bbb')

    @patch('ldap.initialize')
    def test_connection_failure(self, ldapMod):
        ldapMod.side_effect = Exception('broken connection')

        with self.assertRaises(Exception):
            con = reader.LdapConnection('aaa', 'bbb', 'ccc', 'ddd')

    @patch('ldap.initialize')
    def test_auth_failure(self, ldapMod):
        mockcon = Mock()
        mockcon.simple_bind_s.side_effect = Exception('bad credentials')
        
        ldapMod.return_value = mockcon

        with self.assertRaises(Exception):
            con = reader.LdapConnection('aaa', 'bbb', 'ccc', 'ddd')

    @patch('ldap_reader.reader.LdapGroupGroup')
    @patch('ldap_reader.reader.LdapOuGroup')
    @patch('ldap_reader.reader.LdapConnection._determine_group_type')
    @patch('ldap.initialize')
    def test_get_group_correct_type_for_ou(self, ldapMod, d_grp_typ, l_ou_grp, l_grp_grp):
        d_grp_typ.return_value = "ou"
        
        l_ou_grp.return_value = sentinel.ougrp
        l_grp_grp.return_value = sentinel.grpgrp

        con = reader.LdapConnection('aaa', 'bbb', 'ccc', 'ddd')
        ougrp = con.get_group(dict(), 'aaa')

        self.assertIs(ougrp, sentinel.ougrp)

    @patch('ldap_reader.reader.LdapGroupGroup')
    @patch('ldap_reader.reader.LdapOuGroup')
    @patch('ldap_reader.reader.LdapConnection._determine_group_type')
    @patch('ldap.initialize')
    def test_get_group_correct_type_for_group(self, ldapMod, d_grp_typ, l_ou_grp, l_grp_grp):
        d_grp_typ.return_value = "group"
        
        l_ou_grp.return_value = sentinel.ougrp
        l_grp_grp.return_value = sentinel.grpgrp

        con = reader.LdapConnection('aaa', 'bbb', 'ccc', 'ddd')
        grpgrp = con.get_group(dict(), 'aaa')

        self.assertIs(grpgrp, sentinel.grpgrp)


class TestLdapOuGroup(unittest.TestCase):

    def setUp(self):
        self.config = {
            'dir_username_source': 'userPrincipalName',
            'dir_fname_source': 'givenName',
            'dir_lname_source': 'sn',
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
            { 'email': 'Test1@test.local',
              'firstname': 'Billy',
              'lastname': 'Tester',
            },
            { 'email': 'Test2@test.local',
              'firstname': 'Dead',
              'lastname': 'Beef',
            },
            { 'email': 'robot@test.local',
              'firstname': ' ',
              'lastname': ' ',
            },
        ]
        
    @patch('ldap_reader.reader._PagedAsyncSearch')
    def test_userlist(self, mock_pas):
        mock_pas.return_value = self.ldap_results

        grp = reader.LdapOuGroup(MagicMock(), self.config, sentinel.ldap_id)
        users = grp.userlist()
        
        self.assertEqual(self.group_results, users)

    @patch('ldap_reader.reader._PagedAsyncSearch')
    def test_userlist_raises(self, mock_pas):
        mock_pas.return_value = self.ldap_results
        mock_pas.side_effect = Exception('TestException')

        grp = reader.LdapOuGroup(MagicMock(), self.config, sentinel.ldap_id)

        with self.assertRaises(Exception):
            users = grp.userlist()
        
        self.assertEqual(self.group_results, users)
    

if __name__ == "__main__":
    unittest.main()
