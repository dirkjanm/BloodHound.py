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
import traceback

import codecs
from dns import resolver
from ldap3 import ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPKeyError, LDAPAttributeError, LDAPCursorError
# from impacket.krb5.kerberosv5 import KerberosError
from bloodhound.ad.utils import ADUtils, DNSCache
from bloodhound.ad.trusts import ADDomainTrust
from bloodhound.ad.computer import ADComputer


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
            attributes = ALL_ATTRIBUTES
        result = self.ldap.extend.standard.paged_search(searchBase,
                                                        searchFilter,
                                                        attributes=attributes,
                                                        paged_size=200,
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
            logging.warning('Warning: Unknown group %s', membership)

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
            logging.warning('Warning: Unknown primarygroupid %d', primarygroupid)

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
            out.write(trust.to_output()+'\n')
        logging.info('Found %u trusts', entriesNum)

        logging.debug('Finished writing trusts')
        out.close()

    def fetch_all(self):
        self.get_domains()
        self.get_computers()
        self.get_groups()
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

        self.domains = {}
        self.nbdomains = {}
        self.groups = {} # Groups by DN
        self.groups_dnmap = {} # Group mapping from gid to DN
        self.computers = {}
        self.users = {}

        # Create a resolver object
        self.resolver = resolver.Resolver()
        if nameserver:
            self.resolver.nameservers = [nameserver]
        # Give it a cache to prevent duplicate lookups
        self.resolver.cache = resolver.Cache()
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
