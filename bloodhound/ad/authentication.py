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
import os
from binascii import unhexlify
from ldap3 import Server, Connection, NTLM, ALL, SASL, GSSAPI
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT

"""
Active Directory authentication helper
"""
class ADAuthentication(object):
    def __init__(self, username='', password='', domain='',
                 lm_hash='', nt_hash='', aeskey='', kdc=None, kerberos=False):
        self.username = username
        self.domain = domain
        if self.username and '@' in self.username:
            self.username, self.domain = self.username.rsplit('@', 1)
        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.aeskey = aeskey
        self.kdc = kdc

        # Kerberos
        self.kerberos = kerberos
        self.tgt = None

    def set_aeskey(self, aeskey):
        self.aeskey = aeskey

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
        # ldap3 supports auth with the NT hash. LM hash is actually ignored since only NTLMv2 is used.
        if self.nt_hash != '':
            ldappass = self.lm_hash + ':' + self.nt_hash
        else:
            ldappass = self.password
        ldaplogin = '%s\\%s' % (self.domain, self.username)

        if self.kerberos:
            CONNECTION = {"authentication": SASL,
                          "sasl_mechanism": GSSAPI,
                          "check_names": True}
            conn = Connection(server, **CONNECTION)
            logging.debug('Authenticating to LDAP server using current KRB5CCACHE')
            bound = conn.bind()
        else:
            conn = Connection(server, user=ldaplogin, auto_referrals=False, password=ldappass, authentication=NTLM)
            logging.debug('Authenticating to LDAP server using provided credentials')
            bound = conn.bind()

        if not bound:
            result = conn.result
            if result['result'] == RESULT_STRONGER_AUTH_REQUIRED and protocol == 'ldap':
                logging.warning('LDAP Authentication is refused because LDAP signing is enabled. '
                                'Trying to connect over LDAPS instead...')
                return self.getLDAPConnection(hostname, ip, baseDN, 'ldaps')
            else:
                logging.error('Failure to authenticate with LDAP! Error %s' % result['message'])
                return None
        return conn

    def get_tgt(self):
        """
        Request a Kerberos TGT given our provided inputs.
        """
        username = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        logging.info('Getting TGT for user')
        tgt, cipher, _, session_key = getKerberosTGT(username, self.password, self.domain,
                                                     unhexlify(self.lm_hash), unhexlify(self.nt_hash),
                                                     self.aeskey,
                                                     self.kdc)
        TGT = dict()
        TGT['KDC_REP'] = tgt
        TGT['cipher'] = cipher
        TGT['sessionKey'] = session_key
        self.tgt = TGT
