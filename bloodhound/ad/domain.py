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
from ldap3 import ALL_ATTRIBUTES, BASE
from ldap3.core.exceptions import LDAPKeyError, LDAPAttributeError, LDAPCursorError, LDAPNoSuchObjectResult
# from impacket.krb5.kerberosv5 import KerberosError
from bloodhound.ad.utils import ADUtils, DNSCache, SidCache, SamCache
from bloodhound.ad.trusts import ADDomainTrust
from bloodhound.ad.computer import ADComputer
from bloodhound.enumeration.objectresolver import ObjectResolver

"""
Active Directory Domain Controller
"""
class ADDC(ADComputer):
    def __init__(self, hostname=None, ad=None):
        ADComputer.__init__(self, hostname)
        self.ad = ad
        self.ldap = None
        self.gcldap = None

    def ldap_connect(self, protocol='ldap'):
        """
        Connect to the LDAP service
        """
        logging.info('Connecting to LDAP server: %s' % self.hostname)

        # Convert the hostname to an IP, this prevents ldap3 from doing it
        # which doesn't use our custom nameservers
        q = self.ad.dnsresolver.query(self.hostname)
        for r in q:
            ip = r.address

        self.ldap = self.ad.auth.getLDAPConnection(hostname=ip,
                                                   baseDN=self.ad.baseDN, protocol=protocol)
        return self.ldap is not None

    def gc_connect(self, protocol='ldap'):
        """
        Connect to the global catalog
        """
        if self.hostname in self.ad.gcs():
            # This server is a Global Catalog
            server = self.hostname
        else:
            # Pick the first GC server
            try:
                server = self.ad.gcs()[0]
            except IndexError:
                # TODO: implement fallback options for GC detection?
                logging.error('Could not find a Global Catalog in this domain!'\
                              ' Resolving will be unreliable in forests with multiple domains')
                return False
        logging.info('Connecting to GC LDAP server: %s' % server)

        # Convert the hostname to an IP, this prevents ldap3 from doing it
        # which doesn't use our custom nameservers
        q = self.ad.dnsresolver.query(server)
        for r in q:
            ip = r.address

        self.gcldap = self.ad.auth.getLDAPConnection(hostname=ip, gc=True,
                                                     baseDN=self.ad.baseDN, protocol=protocol)
        return self.gcldap is not None

    def search(self, searchFilter='(objectClass=*)', attributes=None, searchBase=None, generator=True, use_gc=False):
        """
        Search for objects in LDAP or Global Catalog LDAP.
        """
        if self.ldap is None:
            self.ldap_connect()
        if searchBase is None:
            searchBase = self.ad.baseDN
        if attributes is None or attributes == []:
            attributes = ALL_ATTRIBUTES
        # Use the GC if this is requested
        if use_gc:
            searcher = self.gcldap
        else:
            searcher = self.ldap
        sresult = searcher.extend.standard.paged_search(searchBase,
                                                        searchFilter,
                                                        attributes=attributes,
                                                        paged_size=200,
                                                        generator=generator)

        # Use a generator for the result regardless of if the search function uses one
        for e in sresult:
            if e['type'] != 'searchResEntry':
                continue
            yield e

    def ldap_get_single(self, qobject, attributes=None, use_gc=False):
        """
        Get a single object, requires full DN to object.
        This function supports searching both in the local directory and the Global Catalog.
        The connection to the GC should already be established before calling this function.
        """
        if use_gc:
            searcher = self.gcldap
        else:
            searcher = self.ldap
        if attributes is None or attributes == []:
            attributes = ALL_ATTRIBUTES
        try:
            sresult = searcher.extend.standard.paged_search(qobject,
                                                            '(objectClass=*)',
                                                            search_scope=BASE,
                                                            attributes=attributes,
                                                            paged_size=10,
                                                            generator=False)
        except LDAPNoSuchObjectResult:
            # This may indicate the object doesn't exist or access is denied
            logging.warning('LDAP Server reported that the object %s does not exist.', qobject)
            return None
        for e in sresult:
            if e['type'] != 'searchResEntry':
                continue
            return e

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
                                  searchBase="CN=Partitions,%s" % self.ldap.server.info.other['configurationNamingContext'][0])
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

    def get_forest_domains(self):
        """
        Function which searches the LDAP references in order to find domains.
        I'm not sure if this is the best function but couldn't find anything better.

        This searches the configuration, which is present only once in the forest but is replicated
        to every DC.
        """
        entries = self.search('(objectClass=crossRef)',
                              ['nETBIOSName', 'systemFlags', 'nCName', 'name'],
                              searchBase="CN=Partitions,%s" % self.ldap.server.info.other['configurationNamingContext'][0],
                              generator=True)

        entriesNum = 0
        for entry in entries:
            # This is a naming context, but not a domain
            if not entry['attributes']['systemFlags'] & 2:
                continue
            entry['attributes']['distinguishedName'] = entry['attributes']['nCName']
            entriesNum += 1
            # Todo: actually use these objects instead of discarding them
            # means rewriting other functions
            d = ADDomain.fromLDAP(entry['attributes']['nCName'])
            self.ad.domains[entry['attributes']['nCName']] = entry
            self.ad.nbdomains[entry['attributes']['nETBIOSName']] = entry

        # Store this number so we can easily determine if we are in a multi-domain
        # forest later on.
        self.ad.num_domains = entriesNum
        logging.info('Found %u domains in the forest', entriesNum)

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
        self.get_forest_domains()
        self.get_computers()
        self.get_groups()
#        self.get_users()
#        self.get_domain_controllers()


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
        # List of DCs for this domain. Contains just one DC since
        # we query for the primary DC specifically
        self._dcs = []
        # Kerberos servers
        self._kdcs = []
        # Global catalog servers
        self._gcs = []

        self.domains = {}
        self.nbdomains = {}
        self.groups = {} # Groups by DN
        self.groups_dnmap = {} # Group mapping from gid to DN
        self.computers = {}
        self.users = {}

        # Create a resolver object
        self.dnsresolver = resolver.Resolver()
        if nameserver:
            self.dnsresolver.nameservers = [nameserver]
        # Give it a cache to prevent duplicate lookups
        self.dnsresolver.cache = resolver.Cache()
        # Default timeout after 3 seconds if the DNS servers
        # do not come up with an answer
        self.dnsresolver.lifetime = 3.0
        # Also create a custom cache for both forward and backward lookups
        # this cache is thread-safe
        self.dnscache = DNSCache()
        # Create a thread-safe SID lookup cache
        self.sidcache = SidCache()
        # Create a thread-safe SAM lookup cache
        self.samcache = SamCache()
        # Object Resolver, initialized later
        self.objectresolver = None
        # Number of domains within the forest
        self.num_domains = 1

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

    def gcs(self):
        return self._gcs

    def kdcs(self):
        return self._kdcs

    def create_objectresolver(self, addc):
        self.objectresolver = ObjectResolver(addomain=self, addc=addc)

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

            q = self.dnsresolver.query(query, 'SRV')

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

        try:
            q = self.dnsresolver.query(query.replace('pdc','gc'), 'SRV')
            for r in q:
                gc = str(r.target).rstrip('.')
                logging.debug('Found Global Catalog server: %s' % gc)
                if gc not in self._gcs:
                    self._gcs.append(gc)

        except resolver.NXDOMAIN:
            pass

        if kerberos is True:
            try:
                q = self.dnsresolver.query('_kerberos._tcp.dc._msdcs', 'SRV')
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
