####################
#
# Copyright (c) 2022 Dirk-jan Mollema (Outsider Security)
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

import os, sys, logging, argparse, getpass, time, re, datetime, codecs, json
from zipfile import ZipFile
from bloodhound.ad.domain import AD, ADDC
from bloodhound.ad.authentication import ADAuthentication
from bloodhound.enumeration.computers import ComputerEnumerator
from bloodhound.enumeration.memberships import MembershipEnumerator
from bloodhound.enumeration.domains import DomainEnumerator

"""
BloodHound.py is a Python port of BloodHound, designed to run on Linux and Windows.
"""
class BloodHound(object):
    def __init__(self, ad):
        self.ad = ad
        self.ldap = None
        self.pdc = None
        self.sessions = []


    def connect(self):
        if len(self.ad.dcs()) == 0:
            logging.error('Could not find a domain controller. Consider specifying a domain and/or DNS server.')
            sys.exit(1)

        if not self.ad.baseDN:
            logging.error('Could not figure out the domain to query. Please specify this manually with -d')
            sys.exit(1)

        pdc = self.ad.dcs()[0]
        logging.debug('Using LDAP server: %s', pdc)
        logging.debug('Using base DN: %s', self.ad.baseDN)

        if len(self.ad.kdcs()) > 0:
            kdc = self.ad.kdcs()[0]
            logging.debug('Using kerberos KDC: %s', kdc)
            logging.debug('Using kerberos realm: %s', self.ad.realm())

        # Create a domain controller object
        self.pdc = ADDC(pdc, self.ad)
        # Create an object resolver
        self.ad.create_objectresolver(self.pdc)

    def run(self, collect=None, num_workers=10, disable_pooling=False, timestamp="", computerfile="", cachefile=None):
        start_time = time.time()
        dncache, sidcache = self.pdc.get_cache_items()
        caches = {'dncache':dncache,'sidcache':sidcache}
        if not cachefile:
            cachefile = 'bhpycache.json'
        with codecs.open(cachefile, 'w', 'utf-8') as outfile:
            json.dump(caches, outfile)
        end_time = time.time()
        minutes, seconds = divmod(int(end_time-start_time),60)
        logging.info('Done in %02dM %02dS' % (minutes, seconds))

def main():
#    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    stream = logging.StreamHandler(sys.stderr)
    stream.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    parser = argparse.ArgumentParser(add_help=True, description='BloodHound.py cache file generator', formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-u',
                        '--username',
                        action='store',
                        help='Username. Format: username[@domain]; If the domain is unspecified, the current domain is used.')
    parser.add_argument('-p',
                        '--password',
                        action='store',
                        help='Password')
    parser.add_argument('--hashes',
                        action='store',
                        help='LM:NLTM hashes')
    parser.add_argument('-ns',
                        '--nameserver',
                        action='store',
                        help='Alternative name server to use for queries')
    parser.add_argument('--dns-tcp',
                        action='store_true',
                        help='Use TCP instead of UDP for DNS queries')
    parser.add_argument('--dns-timeout',
                        action='store',
                        type=int,
                        default=3,
                        help='DNS query timeout in seconds (default: 3)')
    parser.add_argument('-d',
                        '--domain',
                        action='store',
                        help='Domain to query.')
    parser.add_argument('-dc',
                        '--domain-controller',
                        metavar='HOST',
                        action='store',
                        help='Override which DC to query (hostname)')
    parser.add_argument('-gc',
                        '--global-catalog',
                        metavar='HOST',
                        action='store',
                        help='Override which GC to query (hostname)')
    parser.add_argument('--disable-autogc',
                        action='store_true',
                        help='Don\'t automatically select a Global Catalog (use only if it gives errors)')
    parser.add_argument('-v',
                        action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--cachefile',
                        action='store',
                        help='Cache file name')
    args = parser.parse_args()

    if args.v is True:
        logger.setLevel(logging.DEBUG)

    if args.username is not None and args.password is not None:
        logging.debug('Authentication: username/password')
        auth = ADAuthentication(username=args.username, password=args.password, domain=args.domain)
    elif args.username is not None and args.password is None and args.hashes is None:
        args.password = getpass.getpass()
        auth = ADAuthentication(username=args.username, password=args.password, domain=args.domain)
    elif args.username is None and (args.password is not None or args.hashes is not None):
        logging.error('Authentication: password or hashes provided without username')
        sys.exit(1)
    elif args.hashes is not None and args.username is not None:
        logging.debug('Authentication: NTLM hashes')
        lm, nt = args.hashes.split(":")
        auth = ADAuthentication(lm_hash=lm, nt_hash=nt, username=args.username, domain=args.domain)
    else:
        parser.print_help()
        sys.exit(1)

    ad = AD(auth=auth, domain=args.domain, nameserver=args.nameserver, dns_tcp=args.dns_tcp, dns_timeout=args.dns_timeout)

    logging.debug('Using DNS to retrieve domain information')
    ad.dns_resolve(domain=args.domain, options=args)

    # Override the detected DC / GC if specified
    if args.domain_controller:
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', args.domain_controller):
            logging.error('The specified domain controller %s looks like an IP address, but requires a hostname (FQDN).\n'\
                          'Use the -ns flag to specify a DNS server IP if the hostname does not resolve on your default nameserver.',
                          args.domain_controller)
            sys.exit(1)
        ad.override_dc(args.domain_controller)
    if args.global_catalog:
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', args.global_catalog):
            logging.error('The specified global catalog server %s looks like an IP address, but requires a hostname (FQDN).\n'\
                          'Use the -ns flag to specify a DNS server IP if the hostname does not resolve on your default nameserver.',
                          args.global_catalog)
            sys.exit(1)
        ad.override_gc(args.global_catalog)
    # For adding timestamp prefix to the outputfiles 
    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S') + "_"
    bloodhound = BloodHound(ad)
    bloodhound.connect()
    bloodhound.run(timestamp=timestamp,
                   cachefile=args.cachefile)

if __name__ == '__main__':
    main()
