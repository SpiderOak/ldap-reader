from setuptools import setup, find_packages

setup(name = 'ldap-reader',
      version = '0.1',
      package_dir = { 'ldap_reader': 'ldap_reader' },
      packages = [ 'ldap_reader' ],
      install_requires = [ 'python-ldap' ],
      keywords = [ 'spideroak', 'ldap' ],
      description = 'ldap-reader is a module for listing accounts' \
                    ' and authenticating them against LDAP.',
)
