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
import re
import socket
import traceback
from struct import unpack
import dns
import ldap3
from dns import resolver, reversename
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED
from ldap3.core.exceptions import LDAPKeyError, LDAPAttributeError, LDAPCursorError
from impacket.dcerpc.v5 import transport, samr, srvs, lsat, lsad, nrpc
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.dtypes import RPC_SID, MAXIMUM_ALLOWED
from impacket.krb5.kerberosv5 import KerberosError
from impacket.structure import Structure
from utils import ADUtils, DNSCache
from trusts import ADDomainTrust
import Queue
import threading
import codecs

"""
Computer connected to Active Directory
"""
class ADComputer(object):
    def __init__(self, hostname=None, ad=None):
        self.hostname = hostname
        self.ad = ad
        self.rpc = None
        self.dce = None
        self.sids = []
        self.admins = []
        self.trusts = []
        self.addr = None
        self.smbconnection = None


    def try_connect(self):
        addr = None
        try:
            addr = self.ad.dnscache.get(self.hostname)
        except KeyError:
            try:
                q = self.ad.resolver.query(self.hostname, 'A')
                for r in q:
                    addr = r.address

                if addr == None:
                    return False
            # Do exit properly on keyboardinterrupts
            except KeyboardInterrupt:
                raise
            except Exception as e:
                logging.warning('Could not resolve: %s: %s' % (self.hostname, e))
                return False

            logging.debug('Resolved: %s' % addr)

            self.ad.dnscache.put(self.hostname, addr)

        self.addr = addr

        logging.debug('Trying connecting to computer: %s' % self.hostname)
        # We ping the host here, this adds a small overhead for setting up an extra socket
        # but saves us from constructing RPC Objects for non-existing hosts. Also RPC over
        # SMB does not support setting a connection timeout, so we catch this here.
        if ADUtils.tcp_ping(addr, 445) is False:
            return False
        return True


    def dce_rpc_connect(self, binding, uuid):
        logging.debug('DCE/RPC binding: %s' % binding)

        try:
            self.rpc = transport.DCERPCTransportFactory(binding)
            self.rpc.set_connect_timeout(1.0)
            if hasattr(self.rpc, 'set_credentials'):
                self.rpc.set_credentials(self.ad.auth.username, self.ad.auth.password,
                                         domain=self.ad.auth.domain,
                                         lmhash=self.ad.auth.lm_hash,
                                         nthash=self.ad.auth.nt_hash,
                                         aesKey=self.ad.auth.aes_key)

            # TODO: check Kerberos support
            # if hasattr(self.rpc, 'set_kerberos'):
                # self.rpc.set_kerberos(True, self.ad.auth.kdc)
            # Yes we prefer SMB3, but it isn't supported by all OS
            # self.rpc.preferred_dialect(smb3structs.SMB2_DIALECT_30)

            # Re-use the SMB connection if possible
            if self.smbconnection:
                self.rpc.set_smb_connection(self.smbconnection)
            dce = self.rpc.get_dce_rpc()
            dce.connect()
            if self.smbconnection is None:
                self.smbconnection = self.rpc.get_smb_connection()
                # We explicity set the smbconnection back to the rpc object
                # this way it won't be closed when we call disconnect()
                self.rpc.set_smb_connection(self.smbconnection)

# Implement encryption?
#            dce.set_auth_level(NTLM_AUTH_PKT_PRIVACY)
            dce.bind(uuid)
        except DCERPCException as e:
            logging.debug(traceback.format_exc())
            logging.warning('DCE/RPC connection failed: %s' % str(e))
            return None
        except KeyboardInterrupt:
            raise
        except Exception as e:
            logging.debug(traceback.format_exc())
            logging.warning('DCE/RPC connection failed: %s' % e)
            return None
        except:
            logging.warning('DCE/RPC connection failed (unknown error)')
            return None

        return dce

    def rpc_close(self):
        if self.smbconnection:
            self.smbconnection.logoff()

    def rpc_get_sessions(self):
        binding = r'ncacn_np:%s[\PIPE\srvsvc]' % self.addr

        dce = self.dce_rpc_connect(binding, srvs.MSRPC_UUID_SRVS)

        if dce is None:
            logging.warning('Connection failed: %s' % binding)
            return

        try:
            resp = srvs.hNetrSessionEnum(dce, '\x00', NULL, 10)
        except Exception as e:
            if str(e).find('Broken pipe') >= 0:
                return
            else:
                raise

        sessions = []

        for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
            userName = session['sesi10_username'][:-1]
            ip = session['sesi10_cname'][:-1]
            logging.debug('IP %s' % repr(session['sesi10_cname']))
            # Strip \\ from IPs
            if ip[:2] == '\\\\':
                ip=ip[2:]
            # Skip empty IPs
            if ip == '':
                continue
            # Skip our connection
            if userName == self.ad.auth.username:
                continue
            # Skip machine accounts
            if userName[-1] == '$':
                continue
            # Skip local connections
            if ip in ['127.0.0.1','[::1]']:
                continue
            # IPv6 address
            if ip[0] == '[' and ip[-1] == ']':
                ip = ip[1:-1]

            logging.info('User %s is logged in on %s from %s' % (userName, self.hostname, ip))

            sessions.append({'user': userName, 'source': ip, 'target': self.hostname})

        dce.disconnect()

        return sessions

    """
    """
    def rpc_get_domain_trusts(self):
        binding = r'ncacn_np:%s[\PIPE\netlogon]' % self.addr

        dce = self.dce_rpc_connect(binding, nrpc.MSRPC_UUID_NRPC)

        if dce is None:
            logging.warning('Connection failed: %s' % binding)
            return

        try:
            req = nrpc.DsrEnumerateDomainTrusts()
            req['ServerName'] = NULL
            req['Flags'] = 1
            resp = dce.request(req)
        except Exception as e:
            raise e

        for domain in resp['Domains']['Domains']:
            logging.info('Found domain trust from %s to %s' % (self.hostname, domain['NetbiosDomainName']))
            self.trusts.append({'domain': domain['DnsDomainName'],
                                'type': domain['TrustType'],
                                'flags': domain['Flags']})

        dce.disconnect()


    """
    This magic is mostly borrowed from impacket/examples/netview.py
    """
    def rpc_get_local_admins(self):
        binding = r'ncacn_np:%s[\PIPE\samr]' % self.addr

        dce = self.dce_rpc_connect(binding, samr.MSRPC_UUID_SAMR)

        if dce is None:
            logging.warning('Connection failed: %s' % binding)
            return

        try:
            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle']

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']

            sid = RPC_SID()
            sid.fromCanonical('S-1-5-32')

            logging.debug('Opening domain handle')

            resp = samr.hSamrOpenDomain(dce,
                                        serverHandle=serverHandle,
                                        desiredAccess=samr.DOMAIN_LOOKUP | MAXIMUM_ALLOWED,
                                        domainId=sid)
            domainHandle = resp['DomainHandle']

            resp = samr.hSamrOpenAlias(dce,
                                       domainHandle,
                                       desiredAccess=samr.ALIAS_LIST_MEMBERS | MAXIMUM_ALLOWED,
                                       aliasId=544)

            resp = samr.hSamrGetMembersInAlias(dce,
                                               aliasHandle=resp['AliasHandle'])

            for member in resp['Members']['Sids']:
                sid_string = member['SidPointer'].formatCanonical()

                logging.debug('Found SID: %s' % sid_string)

                self.sids.append(sid_string)
        except DCERPCException as e:
            logging.debug('Exception connecting to RPC: %s' % e)
        except Exception as e:
            raise e

        dce.disconnect()


    def rpc_resolve_sids(self):
        binding = r'ncacn_np:%s[\PIPE\lsarpc]' % self.addr

        dce = self.dce_rpc_connect(binding, lsat.MSRPC_UUID_LSAT)

        if dce is None:
            logging.warning('Connection failed')
            return

        try:
            resp = lsat.hLsarOpenPolicy2(dce, lsat.POLICY_LOOKUP_NAMES | MAXIMUM_ALLOWED)
        except Exception as e:
            if str(e).find('Broken pipe') >= 0:
                return
            else:
                raise

        policyHandle = resp['PolicyHandle']

        try:
            resp = lsat.hLsarLookupSids(dce, policyHandle, self.sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        except DCERPCException as e:
            if str(e).find('STATUS_NONE_MAPPED') >= 0:
                logging.warning('SID lookup failed, return status: STATUS_NONE_MAPPED')
                raise
            elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                # Not all could be resolved, work with the ones that could
                resp = e.get_packet()
            else:
                raise

        domains = []
        for entry in resp['ReferencedDomains']['Domains']:
            logging.debug('Found referenced domain: %s' % entry['Name'])
            domains.append(entry['Name'])

        i = 0
        for entry in resp['TranslatedNames']['Names']:
            domain = domains[entry['DomainIndex']]
            domainEntry = self.ad.get_domain_by_name(domain)
            if domainEntry is not None:
                domain = ADUtils.ldap2domain(domainEntry['attributes']['distinguishedName'])

            if entry['Name'] != '':
                logging.debug('Resolved SID to name: %s@%s' % (entry['Name'], domain))
                self.admins.append({'computer': self.hostname,
                                    'name': unicode(entry['Name']),
                                    'use': ADUtils.translateSidType(entry['Use']),
                                    'domain': domain,
                                    'sid': self.sids[i]})
                i = i + 1
            else:
                logging.warning('Resolved name is empty [%s]', entry)

        dce.disconnect()


"""
Active Directory Domain Controller
"""
class ADDC(ADComputer):
    def __init__(self, hostname=None, ad=None):
        ADComputer.__init__(self, hostname)
        self.ad = ad
        self.ldap = None

    def ldap_connect(self, protocol='ldap'):
        logging.info('Connecting to LDAP server: %s' % self.hostname)

        self.ldap = self.ad.auth.getLDAPConnection(hostname=self.hostname,
                                                   baseDN=self.ad.baseDN, protocol=protocol)
        return self.ldap is not None

    def search(self, searchFilter='(objectClass=*)', attributes=None, searchBase=None, generator=True):
        if self.ldap is None:
            self.ldap_connect()
        if searchBase is None:
            searchBase = self.ad.baseDN
        if attributes is None or attributes == []:
            attributes = ldap3.ALL_ATTRIBUTES
        result = self.ldap.extend.standard.paged_search(searchBase,
                                                        searchFilter,
                                                        attributes=attributes,
                                                        paged_size=10,
                                                        generator=generator)

        # Use a generator for the result regardless of if the search function uses one
        for e in result:
            if e['type'] != 'searchResEntry':
                continue
            yield e



    def get_domain_controllers(self):
        entries = self.search('(userAccountControl:1.2.840.113556.1.4.803:=8192)',
                              ['dnshostname', 'samaccounttype', 'samaccountname',
                               'serviceprincipalname'])

        logging.info('Found %u domain controllers' % len(entries))

        return entries


    def get_netbios_name(self, context):
        try:
            entries = self.search('(ncname=%s)' % context,
                                 ['nETBIOSName'],
                                 searchBase="CN=Partitions,CN=Configuration,%s" % self.ldap.server.info.other['rootDomainNamingContext'][0])
        except (LDAPAttributeError, LDAPCursorError) as e:
            logging.warning('Could not determine NetBiosname of the domain: %s' % e)
        return entries.next()


    def get_domains(self):
        entries = self.search('(objectClass=domain)',
                              [],
                              generator=True)

        entriesNum = 0
        for entry in entries:
            entriesNum += 1
            # Todo: actually use these objects instead of discarding them
            # means rewriting other functions
            d = ADDomain.fromLDAP(entry['attributes']['distinguishedName'], entry['attributes']['objectSid'])
            self.ad.domains[entry['attributes']['distinguishedName']] = entry
            try:
                nbentry = self.get_netbios_name(entry['attributes']['distinguishedName'])
                self.ad.nbdomains[nbentry['attributes']['nETBIOSName']] = entry
            except IndexError:
                pass

        logging.info('Found %u domains', entriesNum)

        return entries


    def get_groups(self):
        entries = self.search('(objectClass=group)',
                              ['distinguishedName', 'samaccountname', 'samaccounttype', 'objectsid'],
                              generator=True)

        entriesNum = 0
        for entry in entries:
            entriesNum += 1
            self.ad.groups[entry['attributes']['distinguishedName']] = entry
            # Also add a mapping from GID to DN
            try:
                gid = int(entry['attributes']['objectSid'].split('-')[-1])
                self.ad.groups_dnmap[gid] = entry['attributes']['distinguishedName']
            except KeyError:
                #Somehow we found a group without a sid?
                logging.warning('Could not determine SID for group %s' % entry['attributes']['distinguishedName'])

        logging.info('Found %u groups', entriesNum)

        return entries


    def get_users(self):
        entries = self.search('(objectClass=user)',
                              [],
                              generator=True)

        entriesNum = 0
        for entry in entries:
            entriesNum += 1
            self.ad.users[entry['attributes']['distinguishedName']] = entry

        logging.info('Found %u users', entriesNum)
        return entries


    def get_computers(self):
        entries = self.search('(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))',
                              ['samaccountname', 'distinguishedname',
                               'dnshostname', 'samaccounttype'],
                              generator=True)

        entriesNum = 0
        for entry in entries:
            entriesNum += 1
            self.ad.computers[entry['attributes']['distinguishedName']] = entry

        logging.info('Found %u computers', entriesNum)

        return entries


    @staticmethod
    def get_object_type(resolvedEntry):
        if 'sAMAccountType' not in resolvedEntry:
            return 'unknown'
        return resolvedEntry['sAMAccountType']


    def resolve_ad_entry(self, entry):
        resolved = {}
        account = ''
        dn = ''
        domain = ''
        if entry['attributes']['sAMAccountName']:
            account = entry['attributes']['sAMAccountName']
        if entry['attributes']['distinguishedName']:
            dn = entry['attributes']['distinguishedName']
            domain = ADUtils.ldap2domain(dn)

        resolved['principal'] = unicode('%s@%s' % (account, domain)).upper()
        if not entry['attributes']['sAMAccountName']:
            # This doesn't make sense currently but neither does it in SharpHound.
            # TODO: figure out what the intended result is
            if 'ForeignSecurityPrincipals' in dn:
                resolved['principal'] = domain.upper()
                resolved['type'] = 'foreignsecurityprincipal'
            else:
                resolved['type'] = 'unknown'
        else:
            accountType = entry['attributes']['sAMAccountType']
            if accountType in [268435456, 268435457, 536870912, 536870913]:
                resolved['type'] = 'group'
            elif accountType in [805306369]:
                resolved['type'] = 'computer'
                short_name = account.rstrip('$')
                resolved['principal'] = unicode('%s.%s' % (short_name, domain)).upper()
            elif accountType in [805306368]:
                resolved['type'] = 'user'
            elif accountType in [805306370]:
                resolved['type'] = 'trustaccount'
            else:
                resolved['type'] = 'domain'

        return resolved


    def get_memberships(self):
        entries = self.search('(|(memberof=*)(primarygroupid=*))',
                              ['samaccountname', 'distinguishedname',
                               'dnshostname', 'samaccounttype', 'primarygroupid',
                               'memberof'],
                              generator=False)
        return entries

    def get_sessions(self):
        entries = self.search('(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))',
                              ['homedirectory', 'scriptpath', 'profilepath'])
        return entries

    def get_trusts(self):
        entries = self.search('(objectClass=trustedDomain)',
                              attributes=['flatName', 'name', 'securityIdentifier', 'trustAttributes', 'trustDirection', 'trustType'],
                              generator=True)
        return entries

    def write_membership(self, resolved_entry, membership, out):
        if membership in self.ad.groups:
            parent = self.ad.groups[membership]
            pd = ADUtils.ldap2domain(membership)
            pr = self.resolve_ad_entry(parent)

            out.write(u'%s,%s,%s\n' % (pr['principal'], resolved_entry['principal'], resolved_entry['type']))
        else:
            logging.warning('Warning: Unknown group %d' % membership)

    def write_primary_membership(self, resolved_entry, entry, out):
        try:
            primarygroupid = int(entry['attributes']['primaryGroupID'])
        except (TypeError, KeyError):
            # Doesn't have a primarygroupid, means it is probably a Group instead of a user
            return
        try:
            group = self.ad.groups[self.ad.groups_dnmap[primarygroupid]]
            pr = self.resolve_ad_entry(group)
            out.write('%s,%s,%s\n' % (pr['principal'], resolved_entry['principal'], resolved_entry['type']))
        except KeyError:
            logging.warning('Warning: Unknown primarygroupid %d' % primarygroupid)

    def dump_memberships(self, filename='group_membership.csv'):
        entries = self.get_memberships()

        try:
            logging.debug('Opening file for writing: %s' % filename)
            out = codecs.open(filename, 'w', 'utf-8')
        except:
            logging.warning('Could not write file: %s' % filename)
            return

        logging.debug('Writing group memberships to file: %s' % filename)

        out.write('GroupName,AccountName,AccountType\n')
        entriesNum = 0
        for entry in entries:
            entriesNum += 1
            resolved_entry = self.resolve_ad_entry(entry)
            try:
                for m in entry['attributes']['memberOf']:
                    self.write_membership(resolved_entry, m, out)
            except (KeyError, LDAPKeyError):
                logging.debug(traceback.format_exc())
            self.write_primary_membership(resolved_entry, entry, out)

        logging.info('Found %d memberships', entriesNum)
        logging.debug('Finished writing membership')
        out.close()

    def dump_trusts(self, filename='trusts.csv'):
        entries = self.get_trusts()

        try:
            logging.debug('Opening file for writing: %s' % filename)
            out = codecs.open(filename, 'w', 'utf-8')
        except:
            logging.warning('Could not write file: %s' % filename)
            return


        logging.debug('Writing trusts to file: %s' % filename)

        out.write('SourceDomain,TargetDomain,TrustDirection,TrustType,Transitive\n')
        entriesNum = 0
        for entry in entries:
            entriesNum += 1
            # TODO: self.ad is currently only a single domain. In multi domain mode
            # this will need to be updated
            trust = ADDomainTrust(self.ad.domain, entry['attributes']['name'], entry['attributes']['trustDirection'], entry['attributes']['trustType'], entry['attributes']['trustAttributes'])
            out.write(trust.to_output())
        logging.info('Found %u trusts', entriesNum)

        logging.debug('Finished writing trusts')
        out.close()

    def fetch_all(self):
        self.get_domains()
        self.get_computers()
        self.get_groups()
        self.dump_trusts()
#        self.get_users()
#        self.get_domain_controllers()
        self.dump_memberships()


"""
Active Directory data and cache
"""
class AD(object):
    SID = {
        'S-1-0': 'Null Authority',
        'S-1-0-0': 'Nobody',
        'S-1-1': 'World Authority',
        'S-1-1-0': 'Everyone',
        'S-1-2': 'Local Authority',
        'S-1-2-0': 'Local',
        'S-1-2-1': 'Console Logon',
        'S-1-3': 'Creator Authority',
        'S-1-3-0': 'Creator Owner',
        'S-1-3-1': 'Creator Group',
        'S-1-3-2': 'Creator Owner Server',
        'S-1-3-3': 'Creator Group Server',
        'S-1-3-4': 'Owner Rights',
        'S-1-4': 'Non-unique Authority',
        'S-1-5': 'NT Authority',
        'S-1-5-1': 'Dialup',
        'S-1-5-2': 'Network',
        'S-1-5-3': 'Batch',
        'S-1-5-4': 'Interactive',
        'S-1-5-6': 'Service',
        'S-1-5-7': 'Anonymous',
        'S-1-5-8': 'Proxy',
        'S-1-5-9': 'Enterprise Domain Controllers',
        'S-1-5-10': 'Principal Self',
        'S-1-5-11': 'Authenticated Users',
        'S-1-5-12': 'Restricted Code',
        'S-1-5-13': 'Terminal Server Users',
        'S-1-5-14': 'Remote Interactive Logon',
        'S-1-5-15': 'This Organization',
        'S-1-5-17': 'This Organization',
        'S-1-5-18': 'Local System',
        'S-1-5-19': 'NT Authority',
        'S-1-5-20': 'NT Authority',
        'S-1-5-80-0': 'All Services',
        'S-1-5-32-544': 'BUILTIN\\Administrators',
        'S-1-5-32-545': 'BUILTIN\\Users',
        'S-1-5-32-546': 'BUILTIN\\Guests',
        'S-1-5-32-547': 'BUILTIN\\Power Users',
        'S-1-5-32-548': 'BUILTIN\\Account Operators',
        'S-1-5-32-549': 'BUILTIN\\Server Operators',
        'S-1-5-32-550': 'BUILTIN\\Print Operators',
        'S-1-5-32-551': 'BUILTIN\\Backup Operators',
        'S-1-5-32-552': 'BUILTIN\\Replicators',
        'S-1-5-32-554': 'BUILTIN\\Pre-Windows 2000 Compatible Access',
        'S-1-5-32-555': 'BUILTIN\\Remote Desktop Users',
        'S-1-5-32-556': 'BUILTIN\\Network Configuration Operators',
        'S-1-5-32-557': 'BUILTIN\\Incoming Forest Trust Builders',
        'S-1-5-32-558': 'BUILTIN\\Performance Monitor Users',
        'S-1-5-32-559': 'BUILTIN\\Performance Log Users',
        'S-1-5-32-560': 'BUILTIN\\Windows Authorization Access Group',
        'S-1-5-32-561': 'BUILTIN\\Terminal Server License Servers',
        'S-1-5-32-562': 'BUILTIN\\Distributed COM Users',
        'S-1-5-32-569': 'BUILTIN\\Cryptographic Operators',
        'S-1-5-32-573': 'BUILTIN\\Event Log Readers',
        'S-1-5-32-574': 'BUILTIN\\Certificate Service DCOM Access',
        'S-1-5-32-575': 'BUILTIN\\RDS Remote Access Servers',
        'S-1-5-32-576': 'BUILTIN\\RDS Endpoint Servers',
        'S-1-5-32-577': 'BUILTIN\\RDS Management Servers',
        'S-1-5-32-578': 'BUILTIN\\Hyper-V Administrators',
        'S-1-5-32-579': 'BUILTIN\\Access Control Assistance Operators',
        'S-1-5-32-580': 'BUILTIN\\Access Control Assistance Operators',
    }


    def __init__(self, domain=None, auth=None, nameserver=None):
        self.domain = domain
        self.auth = auth
        self._dcs = []
        self._kdcs = []
        self.blacklist = []
        self.whitelist = []
        self.domains = {}
        self.nbdomains = {}
        self.groups = {} # Groups by DN
        self.groups_dnmap = {} # Group mapping from gid to DN
        self.computers = {}
        self.users = {}
        self.admins = []
        # Create a resolver object
        self.resolver = dns.resolver.Resolver()
        if nameserver:
            self.resolver.nameservers = [nameserver]
        # Give it a cache to prevent duplicate lookups
        self.resolver.cache = dns.resolver.Cache()
        # Default timeout after 3 seconds if the DNS servers
        # do not come up with an answer
        self.resolver.lifetime = 3.0
        # Also create a custom cache for both forward and backward lookups
        # this cache is thread-safe
        self.dnscache = DNSCache()

        if domain is not None:
            self.baseDN = ADUtils.domain2ldap(domain)
        else:
            self.baseDN = None


    def realm(self):
        if self.domain is not None:
            return unicode(self.domain).upper()
        else:
            return None


    def dcs(self):
        return self._dcs


    def kdcs(self):
        return self._kdcs


    def dns_resolve(self, domain=None, kerberos=True):
        logging.debug('Querying domain controller information from DNS')

        basequery = '_ldap._tcp.pdc._msdcs'

        if domain is not None:
            logging.debug('Using domain hint: %s' % str(domain))
            query = '_ldap._tcp.pdc._msdcs.%s' % domain
        else:
            # Assume a DNS search domain is (correctly) configured on the host
            # in which case the resolver will autocomplete our request
            query = basequery

        try:

            q = self.resolver.query(query, 'SRV')

            if str(q.qname).lower().startswith('_ldap._tcp.pdc._msdcs'):
                ad_domain = str(q.qname).lower()[len(basequery):].strip('.')
                logging.info('Found AD domain: %s' % ad_domain)

                self.domain = ad_domain
                if self.auth.domain is None:
                    self.auth.domain = ad_domain
                self.baseDN = ADUtils.domain2ldap(ad_domain)

            for r in q:
                dc = str(r.target).rstrip('.')
                logging.debug('Found primary DC: %s' % dc)
                if dc not in self._dcs:
                    self._dcs.append(dc)

        except resolver.NXDOMAIN:
            pass

        if kerberos is True:
            try:
                q = self.resolver.query('_kerberos._tcp.dc._msdcs', 'SRV')
                for r in q:
                    kdc = str(r.target).rstrip('.')
                    logging.debug('Found KDC: %s' % str(r.target).rstrip('.'))
                    if kdc not in self._kdcs:
                        self._kdcs.append(kdc)
                        self.auth.kdc = self._kdcs[0]
            except resolver.NXDOMAIN:
                pass

        return True


    def get_domain_by_name(self, name):
        for domain, entry in self.domains.iteritems():
            if 'name' in entry['attributes']:
                if entry['attributes']['name'].upper() == name.upper():
                    return entry
        # Also try domains by NETBIOS definition
        for domain, entry in self.nbdomains.iteritems():
            if domain.upper() == name.upper():
                return entry
        return None


    def enumerate_computers(self, num_workers=10):
        """
            Enumerates the computers in the domain. Is threaded, you can specify the number of workers.
            Will spawn threads to resolve computers and obtain sessions.
        """
        q = Queue.Queue()

        result_q = Queue.Queue()
        results_worker = threading.Thread(target=self.write_worker, args=(result_q, 'admins.csv', 'sessions.csv'))
        results_worker.daemon = True
        results_worker.start()

        for _ in range(0, num_workers):
            t = threading.Thread(target=self.work, args=(q,result_q))
            t.daemon = True
            t.start()

        for _, computer in self.computers.iteritems():
            if 'dNSHostName' not in computer['attributes']:
                continue

            hostname = computer['attributes']['dNSHostName']
            if not hostname:
                continue

            if hostname in self.blacklist:
                logging.info('Skipping computer: %s (blacklisted)' % hostname)
                continue
            if len(self.whitelist) > 0 and hostname not in self.whitelist:
                logging.info('Skipping computer: %s (not whitelisted)' % hostname)
                continue

            logging.debug('Putting %s on queue', hostname)
            q.put(hostname)
        q.join()
        result_q.put(None)
        result_q.join()

    def process_computer(self, hostname, results_q):
        """
            Processes a single computer, pushes the results of the computer to the given Queue.
        """
        logging.debug('Querying computer: %s' % hostname)
        c = ADComputer(hostname=hostname, ad=self)
        if c.try_connect() == True:
            # Maybe try connection reuse?
            try:
                sessions = c.rpc_get_sessions()
                c.rpc_get_local_admins()
                c.rpc_resolve_sids()
                c.rpc_close()
                # c.rpc_get_domain_trusts()

                for admin in c.admins:
                    # Put the result on the results queue.
                    results_q.put(('admin',u'%s,%s@%s,%s\n' % (unicode(admin['computer']).upper(),
                                 unicode(admin['name']).upper(),
                                 admin['domain'].upper(),
                                 unicode(admin['use']).lower())))

                if sessions is None:
                    sessions = []

                for ses in sessions:
                    # Todo: properly resolve sAMAccounName in GC
                    # currently only single-domain compatible
                    domain = self.domain
                    user = (u'%s@%s' % (ses['user'], domain)).upper()
                    # Resolve the IP to obtain the host the session is from
                    try:
                        target = self.dnscache.get(ses['source'])
                    except KeyError:
                        target = ADUtils.ip2host(ses['source'], self.resolver)
                        # Even if the result is the IP (aka could not resolve PTR) we still cache
                        # it since this result is unlikely to change
                        self.dnscache.put_single(ses['source'], target)

                    # Put the result on the results queue.
                    results_q.put(('session', u'%s,%s,%u\n' % (user, target, 2)))

            except DCERPCException:
                logging.warning('Querying sessions failed: %s' % hostname)


    def work(self, q, results_q):
        """
            Work function, will obtain work from the given queue and will push results on the results_q.
        """
        logging.debug('Start working')

        while True:
            hostname = q.get()
            logging.info('Querying computer: %s' % hostname)
            self.process_computer(hostname, results_q)
            q.task_done()


    def write_worker(self, result_q, admin_filename, session_filename):
        """
            Worker to write the results from the results_q to the given files.
        """
        admin_out = codecs.open(admin_filename, 'w', 'utf-8')
        session_out = codecs.open(session_filename, 'w', 'utf-8')

        admin_out.write('ComputerName,AccountName,AccountType\n')
        session_out.write('UserName,ComputerName,Weight\n')
        while True:
            obj = result_q.get()

            if obj is None:
                logging.debug('Obtained a None value, exiting')
                break

            t = obj[0]
            data = obj[1]
            if t == 'session':
                session_out.write(data)
                logging.debug('Writing session data to file')
            elif t == 'admin':
                admin_out.write(data)
                logging.debug('Writing admin data to file')
            else:
                logging.warning("Type is %s this should not happen", t)

            result_q.task_done()

        logging.debug('Write worker is done, closing files')
        admin_out.close()
        session_out.close()
        result_q.task_done()




"""
Active Directory Domain
"""
class ADDomain(object):
    def __init__(self, name=None, netbios_name=None, sid=None, distinguishedname=None):
        self.name = name
        self.netbios_name = netbios_name
        self.sid = sid
        self.distinguishedname = distinguishedname


    @staticmethod
    def fromLDAP(identifier, sid=None):
        dns_name = ADUtils.ldap2domain(identifier)
        return ADDomain(name=dns_name, sid=sid, distinguishedname=identifier)
