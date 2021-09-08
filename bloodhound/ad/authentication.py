####################
#
# Copyright (c) 2018 Fox-IT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################

import logging
from ldap3 import Server, Connection, NTLM, ALL, SASL, KERBEROS
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED

"""
Active Directory authentication helper
"""
class ADAuthentication(object):
    def __init__(self, username='', password='', domain='',
                 lm_hash='', nt_hash='', aes_key='', kdc=None):
        self.username = username
        self.domain = domain
        if '@' in self.username:
            self.username, self.domain = self.username.rsplit('@', 1)
        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.aes_key = aes_key
        self.kdc = kdc

    
    def getLDAPConnection(self, hostname='', ip='', baseDN='', protocol='ldaps', gc=False):
        if gc:
            # Global Catalog connection
            if protocol == 'ldaps':
                # Ldap SSL
                server = Server("%s://%s:3269" % (protocol, ip), get_info=ALL)
            else:
                # Plain LDAP
                server = Server("%s://%s:3268" % (protocol, ip), get_info=ALL)
        else:
            server = Server("%s://%s" % (protocol, ip), get_info=ALL)
        if  self.kdc is None:
            # ldap3 supports auth with the NT hash. LM hash is actually ignored since only NTLMv2 is used.
            if self.nt_hash != '':
                ldappass = self.lm_hash + ':' + self.nt_hash
            else:
                ldappass = self.password
            ldaplogin = '%s\\%s' % (self.domain, self.username)
            conn = Connection(server, user=ldaplogin, auto_referrals=False, password=ldappass, authentication=NTLM, receive_timeout=60, auto_range=True)
        else:
            logging.debug('Using Kerberos to authenticate to LDAP server')
            # optional user princial to select the correct ticket
            user_principal = self.username if self.username is not None and len(self.username) > 0 else None
            # we have to use the sasl_credentials to pass the hostname to GSSAPI because server only contains the ip
            server_name = hostname.upper().split(".%s" % self.domain.upper())[0]
            conn = Connection(server, user=user_principal, authentication=SASL, sasl_mechanism=KERBEROS, sasl_credentials=(server_name,))
        logging.debug('Authenticating to LDAP server')
        if not conn.bind():
            result = conn.result
            if result['result'] == RESULT_STRONGER_AUTH_REQUIRED and protocol == 'ldap':
                logging.warning('LDAP Authentication is refused because LDAP signing is enabled. '
                                'Trying to connect over LDAPS instead...')
                return self.getLDAPConnection(hostname, ip, baseDN, 'ldaps')
            else:
                logging.error('Failure to authenticate with LDAP! Error %s' % result['message'])
                return None
        return conn
