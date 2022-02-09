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
from __future__ import unicode_literals
import logging
import socket
import threading
import re
import dns
from dns import resolver, reversename
from bloodhound.ad.structures import LDAP_SID

"""
"""
class ADUtils(object):
    WELLKNOWN_SIDS = {
        "S-1-0": ("Null Authority", "USER"),
        "S-1-0-0": ("Nobody", "USER"),
        "S-1-1": ("World Authority", "USER"),
        "S-1-1-0": ("Everyone", "GROUP"),
        "S-1-2": ("Local Authority", "USER"),
        "S-1-2-0": ("Local", "GROUP"),
        "S-1-2-1": ("Console Logon", "GROUP"),
        "S-1-3": ("Creator Authority", "USER"),
        "S-1-3-0": ("Creator Owner", "USER"),
        "S-1-3-1": ("Creator Group", "GROUP"),
        "S-1-3-2": ("Creator Owner Server", "COMPUTER"),
        "S-1-3-3": ("Creator Group Server", "COMPUTER"),
        "S-1-3-4": ("Owner Rights", "GROUP"),
        "S-1-4": ("Non-unique Authority", "USER"),
        "S-1-5": ("NT Authority", "USER"),
        "S-1-5-1": ("Dialup", "GROUP"),
        "S-1-5-2": ("Network", "GROUP"),
        "S-1-5-3": ("Batch", "GROUP"),
        "S-1-5-4": ("Interactive", "GROUP"),
        "S-1-5-6": ("Service", "GROUP"),
        "S-1-5-7": ("Anonymous", "GROUP"),
        "S-1-5-8": ("Proxy", "GROUP"),
        "S-1-5-9": ("Enterprise Domain Controllers", "GROUP"),
        "S-1-5-10": ("Principal Self", "USER"),
        "S-1-5-11": ("Authenticated Users", "GROUP"),
        "S-1-5-12": ("Restricted Code", "GROUP"),
        "S-1-5-13": ("Terminal Server Users", "GROUP"),
        "S-1-5-14": ("Remote Interactive Logon", "GROUP"),
        "S-1-5-15": ("This Organization ", "GROUP"),
        "S-1-5-17": ("This Organization ", "GROUP"),
        "S-1-5-18": ("Local System", "USER"),
        "S-1-5-19": ("NT Authority", "USER"),
        "S-1-5-20": ("NT Authority", "USER"),
        "S-1-5-80-0": ("All Services ", "GROUP"),
        "S-1-5-32-544": ("Administrators", "GROUP"),
        "S-1-5-32-545": ("Users", "GROUP"),
        "S-1-5-32-546": ("Guests", "GROUP"),
        "S-1-5-32-547": ("Power Users", "GROUP"),
        "S-1-5-32-548": ("Account Operators", "GROUP"),
        "S-1-5-32-549": ("Server Operators", "GROUP"),
        "S-1-5-32-550": ("Print Operators", "GROUP"),
        "S-1-5-32-551": ("Backup Operators", "GROUP"),
        "S-1-5-32-552": ("Replicators", "GROUP"),
        "S-1-5-32-554": ("Pre-Windows 2000 Compatible Access", "GROUP"),
        "S-1-5-32-555": ("Remote Desktop Users", "GROUP"),
        "S-1-5-32-556": ("Network Configuration Operators", "GROUP"),
        "S-1-5-32-557": ("Incoming Forest Trust Builders", "GROUP"),
        "S-1-5-32-558": ("Performance Monitor Users", "GROUP"),
        "S-1-5-32-559": ("Performance Log Users", "GROUP"),
        "S-1-5-32-560": ("Windows Authorization Access Group", "GROUP"),
        "S-1-5-32-561": ("Terminal Server License Servers", "GROUP"),
        "S-1-5-32-562": ("Distributed COM Users", "GROUP"),
        "S-1-5-32-568": ("IIS_IUSRS", "GROUP"),
        "S-1-5-32-569": ("Cryptographic Operators", "GROUP"),
        "S-1-5-32-573": ("Event Log Readers", "GROUP"),
        "S-1-5-32-574": ("Certificate Service DCOM Access", "GROUP"),
        "S-1-5-32-575": ("RDS Remote Access Servers", "GROUP"),
        "S-1-5-32-576": ("RDS Endpoint Servers", "GROUP"),
        "S-1-5-32-577": ("RDS Management Servers", "GROUP"),
        "S-1-5-32-578": ("Hyper-V Administrators", "GROUP"),
        "S-1-5-32-579": ("Access Control Assistance Operators", "GROUP"),
        "S-1-5-32-580": ("Access Control Assistance Operators", "GROUP")
    }

    FUNCTIONAL_LEVELS = {
        0: "2000 Mixed/Native",
        1: "2003 Interim",
        2: "2003",
        3: "2008",
        4: "2008 R2",
        5: "2012",
        6: "2012 R2",
        7: "2016"
    }

    xml_sid_rex = re.compile('<UserId>(S-[0-9\-]+)</UserId>')
    xml_logontype_rex = re.compile('<LogonType>([A-Za-z0-9]+)</LogonType>')

    @staticmethod
    def domain2ldap(domain):
        return 'DC=' + ',DC='.join(str(domain).rstrip('.').split('.'))


    @staticmethod
    def ldap2domain(ldap):
        return re.sub(',DC=', '.', ldap[ldap.find('DC='):], flags=re.I)[3:]


    @staticmethod
    def tcp_ping(host, port, timeout=1.0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.close()
            return True
        except KeyboardInterrupt:
            raise
        except:
            return False

    @staticmethod
    def ip2host(ip, resolver=resolver, use_tcp=False):
        result = ip
        try:
            addr = reversename.from_address(ip)
        except dns.exception.SyntaxError:
            logging.warning('DNS: invalid address: %s' % ip)
            return result

        try:
            answer = str(resolver.query(addr, 'PTR', tcp=use_tcp)[0])
            result = answer.rstrip('.')
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
            pass
        except:
            logging.warning('DNS lookup failed: %s' % addr)
            pass

        return result

    # Translate the binary SID from LDAP into human-readable form
    @staticmethod
    def formatSid(siddata):
        return LDAP_SID(siddata).formatCanonical()

    # Translate SidType to strings accepted by BloodHound
    @staticmethod
    def translateSidType(sidType):
        if sidType == 1:
            return 'User'
        if sidType == 2:
            return 'Group'
        # sidType 4 means "alias", this is actually a Domain Local Group
        if sidType == 4:
            return 'Group'
        if sidType == 9:
            return 'Computer'
        if sidType == 5:
            return 'Wellknown'
        # Can be a (by BloudHound) unsupported type
        # must not be an empty string since this breaks our CSV files
        return 'Unknown'

    @staticmethod
    def resolve_ad_entry(entry):
        """
        Translate an LDAP entry into a dictionary containing the
        information used by BloodHound
        """
        resolved = {}
        dn = ''
        domain = ''

        account = ADUtils.get_entry_property(entry, 'sAMAccountName', '')
        dn = ADUtils.get_entry_property(entry, 'distinguishedName', '')
        if dn != '':
            domain = ADUtils.ldap2domain(dn)
        resolved['objectid'] = ADUtils.get_entry_property(entry, 'objectSid', '')
        resolved['principal'] = ('%s@%s' % (account, domain)).upper()
        if not ADUtils.get_entry_property(entry, 'sAMAccountName'):
            if 'ForeignSecurityPrincipals' in dn:
                resolved['principal'] = domain.upper()
                resolved['type'] = 'foreignsecurityprincipal'
                if 'name' in entry['attributes']:
                    # Fix wellknown entries
                    ename = entry['attributes']['name']
                    if ename in ADUtils.WELLKNOWN_SIDS:
                        name, sidtype = ADUtils.WELLKNOWN_SIDS[ename]
                        resolved['type'] = sidtype.capitalize()
                        resolved['principal'] = ('%s@%s' % (name, domain)).upper()
                        # Well-known have the domain prefix since 3.0
                        resolved['objectid'] = '%s-%s' % (domain.upper(), resolved['objectid'])
                    else:
                        # Foreign security principal
                        resolved['objectid'] = ename
            else:
                resolved['type'] = 'Unknown'
        else:
            accountType = ADUtils.get_entry_property(entry, 'sAMAccountType')
            if accountType in [268435456, 268435457, 536870912, 536870913]:
                resolved['type'] = 'Group'
            elif ADUtils.get_entry_property(entry, 'msDS-GroupMSAMembership', default=b'', raw=True) != b'':
                resolved['type'] = 'User'
                short_name = account.rstrip('$')
                resolved['principal'] = ('%s@%s' % (short_name, domain)).upper()
            elif accountType in [805306369]:
                resolved['type'] = 'Computer'
                short_name = account.rstrip('$')
                resolved['principal'] = ('%s.%s' % (short_name, domain)).upper()
            elif accountType in [805306368]:
                resolved['type'] = 'User'
            elif accountType in [805306370]:
                resolved['type'] = 'trustaccount'
            else:
                resolved['type'] = 'Domain'

        return resolved

    @staticmethod
    def resolve_sid_entry(entry, domain):
        """
        Convert LsarLookupSids entries to entries for the SID cache, which should match
        the format from the resolve_ad_entry function.
        """
        resolved = {}
        account = entry['Name']

        resolved['principal'] = ('%s@%s' % (account, domain)).upper()
        resolved['type'] = ADUtils.translateSidType(entry['Use']).lower()

        # Computer accounts have a different type
        if resolved['type'] == 'computer':
            short_name = account.rstrip('$')
            resolved['principal'] = ('%s.%s' % (short_name, domain)).upper()

        return resolved

    @staticmethod
    def get_entry_property(entry, prop, default=None, raw=False):
        """
        Simple wrapper that gets an attribute from ldap3 dictionary,
        converting empty values to the default specified. This is primarily
        for output to JSON
        """
        try:
            if raw:
                value = entry['raw_attributes'][prop]
            else:
                value = entry['attributes'][prop]
        # Doesn't exist
        except KeyError:
            return default
        # Empty -> return default
        if value == []:
            return default
        try:
            # One value and we don't expect a list -> return the first value
            if len(value) == 1 and default != []:
                return value[0]
        except TypeError:
            # Value doesn't have a len() attribute, so we skip this
            pass
        return value

    @staticmethod
    def win_timestamp_to_unix(seconds):
        """
        Convert Windows timestamp (100 ns since 1 Jan 1601) to
        unix timestamp.
        """
        seconds = int(seconds)
        if seconds == 0:
            return 0
        return int((seconds - 116444736000000000) / 10000000)

    @staticmethod
    def parse_task_xml(xml):
        """
        Parse scheduled task XML and extract the user and logon type with
        regex. Is not a good way to parse XMLs but saves us the whole parsing
        overhead.
        """
        res = ADUtils.xml_sid_rex.search(xml)
        if not res:
            return None
        sid = res.group(1)
        res = ADUtils.xml_logontype_rex.search(xml)
        if not res:
            return None
        logon_type = res.group(1)
        return (sid, logon_type)

    @staticmethod
    def ensure_string(data):
        """
        Sometimes properties can contain binary data. Since we can't assume encoding, make
        sure it can be outputted as json
        """
        if isinstance(data, bytes):
            data = repr(data)
        return data


class AceResolver(object):
    """
    This class resolves ACEs containing rights, acetype and a SID to Aces containing
    BloodHound principals, which can be outputted to json.
    This is mostly a wrapper around the sid resolver calls
    """
    def __init__(self, addomain, resolver):
        self.addomain = addomain
        self.resolver = resolver

    def resolve_aces(self, aces):
        aces_out = []
        for ace in aces:
            out = {
                'RightName': ace['rightname'],
                'IsInherited': ace['inherited']
            }
            # Is it a well-known sid?
            if ace['sid'] in ADUtils.WELLKNOWN_SIDS:
                out['PrincipalSID'] = u'%s-%s' % (self.addomain.domain.upper(), ace['sid'])
                out['PrincipalType'] = ADUtils.WELLKNOWN_SIDS[ace['sid']][1].capitalize()
            else:
                try:
                    entry = self.addomain.sidcache.get(ace['sid'])
                except KeyError:
                    # Look it up instead
                    # Is this SID part of the current domain? If not, use GC
                    use_gc = not ace['sid'].startswith(self.addomain.domain_object.sid)
                    ldapentry = self.resolver.resolve_sid(ace['sid'], use_gc)
                    # Couldn't resolve...
                    if not ldapentry:
                        logging.warning('Could not resolve SID: %s', ace['sid'])
                        # Fake it
                        entry = {
                            'type': 'Unknown',
                            'principal': ace['sid']
                        }
                    else:
                        entry = ADUtils.resolve_ad_entry(ldapentry)
                    # Entries are cached regardless of validity - unresolvable sids
                    # are not likely to be resolved the second time and this saves traffic
                    self.addomain.sidcache.put(ace['sid'], entry)
                out['PrincipalSID'] = ace['sid']
                out['PrincipalType'] = entry['type']
            aces_out.append(out)
        return aces_out

    def resolve_sid(self, sid):
        out = {}
        # Is it a well-known sid?
        if sid in ADUtils.WELLKNOWN_SIDS:
            out['ObjectID'] = u'%s-%s' % (self.addomain.domain.upper(), sid)
            out['ObjectType'] = ADUtils.WELLKNOWN_SIDS[sid][1].capitalize()
        else:
            try:
                entry = self.addomain.sidcache.get(sid)
            except KeyError:
                # Look it up instead
                # Is this SID part of the current domain? If not, use GC
                use_gc = not sid.startswith(self.addomain.domain_object.sid)
                ldapentry = self.resolver.resolve_sid(sid, use_gc)
                # Couldn't resolve...
                if not ldapentry:
                    logging.warning('Could not resolve SID: %s', sid)
                    # Fake it
                    entry = {
                        'type': 'Unknown',
                        'principal':sid
                    }
                else:
                    entry = ADUtils.resolve_ad_entry(ldapentry)
                # Entries are cached regardless of validity - unresolvable sids
                # are not likely to be resolved the second time and this saves traffic
                self.addomain.sidcache.put(sid, entry)
            out['ObjectID'] = sid
            out['ObjectType'] = entry['type']
        return out

class DNSCache(object):
    """
    A cache used for caching forward and backward DNS at the same time.
    This cache is used to avoid PTR queries when forward lookups are already done
    """
    def __init__(self):
        self.lock = threading.Lock()
        self._cache = {}

    # Get an entry from the cache
    def get(self, entry):
        with self.lock:
            return self._cache[entry]

    # Put a forward lookup in the cache, this also
    # puts the reverse lookup in the cache
    def put(self, entry, value):
        with self.lock:
            self._cache[entry] = value
            self._cache[value] = entry

    # Put a reverse lookup in the cache. Forward lookup
    # is not added since reverse is considered less reliable
    def put_single(self, entry, value):
        with self.lock:
            self._cache[entry] = value

class SidCache(object):
    """
    Generic cache for caching SID lookups
    """
    def __init__(self):
        self.lock = threading.Lock()
        self._cache = {}

    # Get an entry from the cache
    def get(self, entry):
        with self.lock:
            return self._cache[entry]

    # Put a forward lookup in the cache, this also
    # puts the reverse lookup in the cache
    def put(self, entry, value):
        with self.lock:
            self._cache[entry] = value

class SamCache(SidCache):
    """
    Cache for mapping SAM names to principals.
    Identical to the SidCache in behaviour
    """
    pass
