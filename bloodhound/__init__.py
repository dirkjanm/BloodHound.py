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

import os, sys, logging, argparse, getpass
from bloodhound.ad.domain import AD, ADDC
from bloodhound.ad.authentication import ADAuthentication
from bloodhound.enumeration.computers import ComputerEnumerator
from bloodhound.enumeration.memberships import MembershipEnumerator
from bloodhound.enumeration.trusts import TrustsEnumerator

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
#        self.pdc.ldap_connect(self.ad.auth.username, self.ad.auth.password, kdc)


    def run(self, collect, num_workers=10):
        if 'group' in collect or 'objectprops' in collect:
            # Fetch domains/computers for later
            self.pdc.prefetch_info('objectprops' in collect, 'acls' in collect)
            # Initialize enumerator
            membership_enum = MembershipEnumerator(self.ad, self.pdc, collect)
            membership_enum.enumerate_memberships()
        elif 'localadmin' in collect or 'session' in collect or 'loggedon' in collect:
            # We need to know which computers to query regardless
            # We also need the domains to have a mapping from NETBIOS -> FQDN for local admins
            self.pdc.prefetch_info('objectprops' in collect, 'acls' in collect)
        elif 'trusts' in collect:
            # Prefetch domains
            self.pdc.get_domains()
        if 'trusts' in collect:
            trusts_enum = TrustsEnumerator(self.ad, self.pdc)
            trusts_enum.dump_trusts()
        if 'localadmin' in collect or 'session' in collect:
            # If we don't have a GC server, don't use it for deconflictation
            have_gc = len(self.ad.gcs()) > 0
            computer_enum = ComputerEnumerator(self.ad, collect, do_gc_lookup=have_gc)
            computer_enum.enumerate_computers(self.ad.computers, num_workers=num_workers)

        logging.info('Done')

def resolve_collection_methods(methods):
    """
    Convert methods (string) to list of validated methods to resolve
    """
    valid_methods = ['group', 'localadmin', 'session', 'trusts', 'default', 'all', 'loggedon',
                     'objectprops']
    default_methods = ['group', 'localadmin', 'session', 'trusts']
    # Similar to SharpHound, All is not really all, it excludes loggedon
    all_methods = ['group', 'localadmin', 'session', 'trusts', 'objectprops']
    if ',' in methods:
        method_list = [method.lower() for method in methods.split(',')]
        validated_methods = []
        for method in method_list:
            if method not in valid_methods:
                logging.error('Invalid collection method specified: %s', method)
                return False

            if method == 'default':
                validated_methods += default_methods
            elif method == 'all':
                validated_methods += all_methods
            else:
                validated_methods.append(method)
        return set(validated_methods)
    else:
        validated_methods = []
        # It is only one
        method = methods.lower()
        if method in valid_methods:
            if method == 'default':
                validated_methods += default_methods
            elif method == 'all':
                validated_methods += all_methods
            else:
                validated_methods.append(method)
            return set(validated_methods)
        else:
            logging.error('Invalid collection method specified: %s', method)
            return False

def main():
#    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    stream = logging.StreamHandler(sys.stderr)
    stream.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)s: %(message)s')
#    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    parser = argparse.ArgumentParser(add_help=True, description='Python based ingestor for BloodHound\nFor help or reporting issues, visit https://github.com/Fox-IT/BloodHound.py', formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-c',
                        '--collectionmethod',
                        action='store',
                        default='Default',
                        help='Which information to collect. Supported: Group, LocalAdmin, Session, '
                             'Trusts, Default (all previous), LoggedOn, ObjectProps, All (all except LoggedOn). '
                             'You can specify more than one by separating them with a comma. (default: Default)')
    parser.add_argument('-d',
                        '--domain',
                        action='store',
                        help='Domain to query.')
    parser.add_argument('-v',
                        action='store_true',
                        help='Enable verbose output')
    helptext = 'Specify one or more authentication options. \n' \
               'By default Kerberos authentication is used and NTLM is used as fallback. \n' \
               'Kerberos tickets are automatically requested if a password or hashes are specified.'
    auopts = parser.add_argument_group('authentication options', description=helptext)
    auopts.add_argument('-u',
                        '--username',
                        action='store',
                        help='Username. Format: username[@domain]; If the domain is unspecified, the current domain is used.')
    auopts.add_argument('-p',
                        '--password',
                        action='store',
                        help='Password')
    auopts.add_argument('-k',
                        '--kerberos',
                        action='store_true',
                        help='Attempt to load ccache file with Kerberos tickets. '
                             'Filename is specified in the KRB5CCNAME environment variable')
    auopts.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    auopts.add_argument('--hashes',
                        action='store',
                        help='LM:NLTM hashes')
    auopts.add_argument('-aesKey',
                        action="store",
                        metavar="hex key",
                        help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    auopts.add_argument('--no-ntlm',
                        action='store_true',
                        help='Do not use NTLM authentication as fallback')
    coopts = parser.add_argument_group('collection options')
    coopts.add_argument('-ns',
                        '--nameserver',
                        action='store',
                        help='Alternative name server to use for queries')
    coopts.add_argument('--dns-tcp',
                        action='store_true',
                        help='Use TCP instead of UDP for DNS queries')
    coopts.add_argument('-dc',
                        '--domain-controller',
                        metavar='HOST',
                        action='store',
                        help='Override which DC to query')
    coopts.add_argument('-gc',
                        '--global-catalog',
                        metavar='HOST',
                        action='store',
                        help='Override which GC to query')
    coopts.add_argument('-w',
                        '--workers',
                        action='store',
                        type=int,
                        default=10,
                        help='Number of workers for computer enumeration (default: 10)')

    args = parser.parse_args()

    if args.v is True:
        logger.setLevel(logging.DEBUG)

    if args.username is not None and args.password is not None:
        logging.debug('Authentication: username/password')
        auth = ADAuthentication(username=args.username, password=args.password, domain=args.domain)
    elif args.username is not None and args.password is None and args.hashes is None and not args.no_pass:
        args.password = getpass.getpass()
        auth = ADAuthentication(username=args.username, password=args.password, domain=args.domain)
    elif args.username is None and (args.password is not None or args.hashes is not None or args.aesKey is not None):
        logging.error('Authentication: password or hashes provided without username')
        sys.exit(1)
    elif (args.hashes is not None or args.aesKey is not None) and args.username is not None:
        if args.hashes:
            logging.debug('Authentication: NTLM hashes')
            lm, nt = args.hashes.split(":")
            auth = ADAuthentication(lm_hash=lm, nt_hash=nt, username=args.username, domain=args.domain)
            if args.aesKey:
                logging.debug('Authentication: Kerberos AES')
                auth.set_aeskey(args.aesKey)
        else:
            logging.debug('Authentication: Kerberos AES')
            auth = ADAuthentication(username=args.username, domain=args.domain, aeskey=args.aesKey)
    else:
        if not args.kerberos:
            parser.print_help()
            sys.exit(1)
        else:
            auth = ADAuthentication(username=args.username, password=args.password, domain=args.domain)

    ad = AD(auth=auth, domain=args.domain, nameserver=args.nameserver, dns_tcp=args.dns_tcp)

    # Resolve collection methods
    collect = resolve_collection_methods(args.collectionmethod)
    if not collect:
        return
    logging.debug('Resolved collection methods: %s', ', '.join(list(collect)))

    logging.debug('Using DNS to retrieve domain information')
    ad.dns_resolve(domain=args.domain)

    # Override the detected DC / GC if specified
    if args.domain_controller:
        ad.override_dc(args.domain_controller)
    if args.global_catalog:
        ad.override_gc(args.global_catalog)

    if args.kerberos is True:
        logging.debug('Authentication: Kerberos ccache')
        # kerberize()
        if not auth.load_ccache():
            logging.debug('Could not load ticket from ccache, trying to request a TGT instead')
            auth.get_tgt()
    else:
        auth.get_tgt()

    bloodhound = BloodHound(ad)
    bloodhound.connect()
    bloodhound.run(collect=collect,
                   num_workers=args.workers)


if __name__ == '__main__':
    main()
