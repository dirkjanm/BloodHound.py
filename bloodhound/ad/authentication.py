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
import ssl
import os
import traceback
from bloodhound.ad.utils import CollectionException
from binascii import unhexlify
from ldap3 import Server, Connection, NTLM, ALL, SASL, KERBEROS, Tls
from ldap3.core.exceptions import LDAPCommunicationError
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal, Ticket
from pyasn1.codec.der import decoder
from impacket.krb5.asn1 import AS_REP, TGS_REP
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from ldap3_ad_auth import bind_kerberos, bind_ntlm, ProtectionError

"""
Active Directory authentication helper
"""
class ADAuthentication(object):
    def __init__(self, username='', password='', domain='',
                 lm_hash='', nt_hash='', aeskey='', kdc=None, auth_method='auto', ldap_channel_binding=False, ldaps_legacy_tls=False):
        self.username = username
        # Assume user domain and enum domain are same
        self.domain = domain.lower()
        self.userdomain = domain.lower()
        # If not, override userdomain
        if '@' in self.username:
            self.username, self.userdomain = self.username.lower().rsplit('@', 1)
        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.aeskey = aeskey
        # KDC for domain we query
        self.kdc = kdc
        # KDC for domain of the user - fill with domain first, will be resolved later
        self.userdomain_kdc = self.domain
        self.auth_method = auth_method
        self.ldap_channel_binding = ldap_channel_binding
        self.ldaps_legacy_tls = ldaps_legacy_tls

        # Kerberos
        self.tgt = None

    def set_aeskey(self, aeskey):
        self.aeskey = aeskey

    def set_kdc(self, kdc):
        # Set KDC
        self.kdc = kdc
        if self.userdomain == self.domain:
            # Also set it for user domain if this is equal
            self.userdomain_kdc = kdc

    def getLDAPConnection(self, hostname='', ip='', baseDN='', protocol='ldaps', gc=False):
        if gc:
            # Global Catalog connection
            if protocol == 'ldaps':
                if self.ldaps_legacy_tls is True:
                    logging.debug("Using legacy LDAPS TLS settings")
                    version=ssl.PROTOCOL_TLSv1_2
                    tls = Tls(validate=ssl.CERT_NONE, version=version, ciphers='ALL:@SECLEVEL=0')
                    server = Server(
                        "%s://%s:3269" % (protocol,ip),
                        use_ssl=True,
                        get_info=ALL,
                        tls=tls
                    )
                else:
                    # LDAPS with default TLS settings
                    server = Server("%s://%s:3269" % (protocol, ip), get_info=ALL)
            else:
                # Plain LDAP
                server = Server("%s://%s:3268" % (protocol, ip), get_info=ALL)
        else: # no GC specified
            if protocol == 'ldaps' and self.ldaps_legacy_tls is True:
                logging.debug("Using legacy LDAPS TLS settings")
                version=ssl.PROTOCOL_TLSv1_2
                tls = Tls(validate=ssl.CERT_NONE, version=version, ciphers='ALL:@SECLEVEL=0')
                server = Server(
                    "%s://%s" % (protocol,ip),
                    use_ssl=True,
                    get_info=ALL,
                    tls=tls
                )
            else: # Use requested LDAP or LDAPS
                server = Server("%s://%s" % (protocol, ip), get_info=ALL)
        # ldap3 supports auth with the NT hash. LM hash is actually ignored since only NTLMv2 is used.
        if self.nt_hash != '':
            if self.lm_hash != '':
                ldappass = self.lm_hash + ':' + self.nt_hash
            else:
                # ldap3 requires a 32-character long string for LM hash in order to use the NT hash
                ldappass = 'aad3b435b51404eeaad3b435b51404ee:' + self.nt_hash
        else:
            ldappass = self.password
        ldaplogin = '%s\\%s' % (self.userdomain, self.username)

        bound = False
        conn = None
        bind_error = None
        if self.tgt is not None and self.auth_method in ('kerberos', 'auto'):
            conn = Connection(server, user=ldaplogin, auto_referrals=False, password=ldappass, authentication=SASL, sasl_mechanism=KERBEROS, receive_timeout=60, auto_range=True)
            logging.debug('Authenticating to LDAP server with Kerberos')
            try:
                bound = self.ldap_kerberos(conn, hostname)
            except Exception as exc:
                if isinstance(exc, LDAPCommunicationError) and isinstance(exc, ProtectionError):
                    logging.error('Protected LDAP connection failed: %s', exc)
                    raise CollectionException('Could not verify protected LDAP connection.') from exc
                bind_error = exc
                if self.auth_method == 'auto':
                    logging.debug(traceback.format_exc())
                    logging.warning('Kerberos auth to LDAP failed, trying NTLM')
                    bound = False
                else:
                    logging.debug(traceback.format_exc())
                    logging.critical('Kerberos auth to LDAP failed, no authentication methods left')
                    raise CollectionException('Could not authenticate to LDAP. Check your credentials and LDAP server requirements.') from exc
        if not bound and self.auth_method in ('auto','ntlm'):
            conn = Connection(server, user=ldaplogin, auto_referrals=False, password=ldappass, authentication=NTLM, receive_timeout=60, auto_range=True)
            logging.debug('Authenticating to LDAP server with NTLM')
            try:
                bind_ntlm(conn, domain=self.userdomain, username=self.username,
                          password=self.password, lm_hash=self.lm_hash,
                          nt_hash=self.nt_hash)
                bound = True
            except Exception as exc:
                logging.debug(traceback.format_exc())
                if isinstance(exc, LDAPCommunicationError) and isinstance(exc, ProtectionError):
                    logging.error('Protected LDAP connection failed: %s', exc)
                    raise CollectionException('Could not verify protected LDAP connection.') from exc
                bind_error = exc

        if not bound:
            if conn is None and self.auth_method == 'kerberos':
                raise CollectionException('Kerberos authentication requested without a TGT.')
            result = conn.result if conn is not None else None
            result = result or {'result': None, 'message': 'protected bind failed'}
            if result['result'] == RESULT_STRONGER_AUTH_REQUIRED and protocol == 'ldap':
                logging.warning('LDAP Authentication is refused because LDAP signing is enabled. '
                                'Trying to connect over LDAPS instead...')
                return self.getLDAPConnection(hostname, ip, baseDN, 'ldaps')
            else:
                message = str(bind_error) if bind_error is not None and result['result'] in (None, 0) else result.get('message')
                logging.error('Failure to authenticate with LDAP! Error %s : Code: %s' % (message, result['result']))
                raise CollectionException('Could not authenticate to LDAP. Check your credentials and LDAP server requirements.') from bind_error
        return conn

    def ldap_kerberos(self, connection, hostname):
        bind_kerberos(connection, hostname=hostname, domain=self.domain,
                      user_domain=self.userdomain, username=self.username,
                      kdc=self.kdc, tgt=self.tgt)
        return True

    def get_tgt(self):
        """
        Request a Kerberos TGT given our provided inputs.
        """
        username = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        logging.info('Getting TGT for user')

        try:
            tgt, cipher, _, session_key = getKerberosTGT(username, self.password, self.userdomain,
                                                         unhexlify(self.lm_hash), unhexlify(self.nt_hash),
                                                         self.aeskey,
                                                         self.userdomain_kdc)
        except Exception as exc:
            logging.debug(traceback.format_exc())
            if self.auth_method == 'auto':
                logging.warning('Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: %s', str(exc))
                return
            else:
                # No other auth methods, so raise exception
                logging.error('Failed to get Kerberos TGT.')
                raise

        if self.userdomain != self.domain:
            # Try to get inter-realm TGT
            username = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            servername = Principal('krbtgt/%s' % self.domain, type=constants.PrincipalNameType.NT_SRV_INST.value)
            # Get referral TGT
            tgs, cipher, _, sessionkey = getKerberosTGS(servername, self.userdomain, self.userdomain_kdc,
                                                                    tgt, cipher, session_key)
            # See if this is a ticket for the correct domain
            refneeded = True
            while refneeded:
                decoded_tgs = decoder.decode(tgs, asn1Spec = TGS_REP())[0]
                next_realm = str(decoded_tgs['ticket']['sname']['name-string'][1])
                if next_realm.upper() == self.domain.upper():
                    refneeded = False
                else:
                    # Get next referral TGT
                    logging.debug('Following referral across trust to get next TGT')
                    servername = Principal('krbtgt/%s' % self.domain, type=constants.PrincipalNameType.NT_SRV_INST.value)
                    tgs, cipher, _, sessionkey = getKerberosTGS(servername, next_realm, next_realm,
                                                                            tgs, cipher, sessionkey)

            # Get foreign domain TGT
            servername = Principal('krbtgt/%s' % self.domain, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, _, sessionkey = getKerberosTGS(servername, self.domain, self.kdc,
                                                                    tgs, cipher, sessionkey)
            # Store this as our TGT
            self.tgt = {
                'KDC_REP': tgs,
                'cipher': cipher,
                'sessionKey': sessionkey
            }
        else:
            TGT = dict()
            TGT['KDC_REP'] = tgt
            TGT['cipher'] = cipher
            TGT['sessionKey'] = session_key
            self.tgt = TGT

    def get_tgs_for_smb(self, hostname):
        """
        Get a TGS for use with SMB Connection. We do this here to make sure the realms are correct,
        since impacket doesn't support cross-realm TGT usage and we don't want it to do its own Kerberos
        """
        username = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        servername = Principal('cifs/%s' % hostname, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, _, sessionkey = getKerberosTGS(servername, self.domain, self.kdc,
                                                                self.tgt['KDC_REP'], self.tgt['cipher'], self.tgt['sessionKey'])
        return {
            'KDC_REP': tgs,
            'cipher': cipher,
            'sessionKey': sessionkey
        }

    def load_ccache(self):
        """
        Extract a TGT from a ccache file.
        """
        # If the kerberos credential cache is known, use that.
        krb5cc = os.getenv('KRB5CCNAME')

        # Otherwise, guess it.
        if krb5cc is None:
            try:
                krb5cc = '/tmp/krb5cc_%u' % os.getuid()
            except AttributeError:
                # This fails on Windows
                krb5cc = 'nonexistingfile'

        if os.path.isfile(krb5cc):
            logging.debug('Using kerberos credential cache: %s', krb5cc)
        else:
            logging.debug('No Kerberos credential cache file found, manually requesting TGT')
            return False

        # Load TGT for our domain
        ccache = CCache.loadFile(krb5cc)
        principal = 'krbtgt/%s@%s' % (self.domain.upper(), self.domain.upper())
        creds = ccache.getCredential(principal, anySPN=False)
        if creds is not None:
            TGT = creds.toTGT()
            # This we store for later
            self.tgt = TGT
            tgt, cipher, session_key = TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
            logging.info('Using TGT from cache')
        else:
            logging.debug("No valid credentials found in cache. ")
            return False

        # Verify if this ticket is actually for the specified user
        ticket = Ticket()
        decoded_tgt = decoder.decode(tgt, asn1Spec = AS_REP())[0]
        ticket.from_asn1(decoded_tgt['ticket'])

        tgt_principal = Principal()
        tgt_principal.from_asn1(decoded_tgt, 'crealm', 'cname')
        expected_principal = '%s@%s' % (self.username.lower(), self.domain.upper())
        if expected_principal.upper() != str(tgt_principal).upper():
            logging.warning('Username in ccache file does not match supplied username! %s != %s', tgt_principal, expected_principal)
            return False
        else:
            logging.info('Found TGT with correct principal in ccache file.')
        return True
