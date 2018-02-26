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
from impacket.ldap import ldapasn1
from bloodhound.ad import AD, ADDC, ADAuthentication


"""
BloodHound.py is a Python port of BloodHound, designed to run on Linux. It may very
well work on other platforms, this is currently untested. Knock yourself out.
"""
class BloodHound:
    def __init__(self, ad):
        self.ad = ad
        self.ldap = None
        self.dc = None
        self.sessions = []


    def connect(self):
        if len(self.ad.dcs()) == 0:
            logging.error('I have no information about the domain')
            sys.exit(1)

        dc = self.ad.dcs()[0]
        logging.debug('Using LDAP server: %s' % dc)
        logging.debug('Using base DN: %s' % self.ad.baseDN)

        if len(self.ad.kdcs()) > 0:
            kdc = self.ad.kdcs()[0]
            logging.debug('Using kerberos KDC: %s' % kdc)
            logging.debug('Using kerberos realm: %s' % self.ad.realm())

        self.dc = ADDC(dc, self.ad)
#        self.dc.ldap_connect(self.ad.auth.username, self.ad.auth.password, kdc)


    def run(self, skip_groups=False, skip_computers=False):
        if not skip_groups:
            self.dc.fetch_all()
        elif not skip_computers:
            # We need to know which computers to query regardless
            self.dc.get_computers()

        if not skip_computers:
            self.ad.fetch_sessions()
            self.ad.dump_admins()

        logging.info('Done')


def kerberize():
    # If the kerberos credential cache is known, use that.
    krb5cc = os.getenv('KRB5CCNAME')

    # Otherwise, guess it.
    if krb5cc is None:
        krb5cc = '/tmp/krb5cc_%u' % os.getuid()

    if os.path.isfile(krb5cc):
        logging.debug('Using kerberos credential cache: %s' % krb5cc)
        if os.getenv('KRB5CCNAME') is None:
            os.environ['KRB5CCNAME'] = krb5cc
    else:
        logging.error('Could not find kerberos credential cache file')
        sys.exit(1)


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

    parser = argparse.ArgumentParser(add_help=True, description='Python based ingestor for BloodHound\nThis tool is in BETA!\nFor help or reporting issues, visit https://github.com/Fox-IT/BloodHound.py', formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-u',
                        '--username',
                        action='store',
                        help='Username')
    parser.add_argument('-p',
                        '--password',
                        action='store',
                        help='Password')
    parser.add_argument('-k',
                        '--kerberos',
                        action='store_true',
                        help='Use kerberos')
    parser.add_argument('--hashes',
                        action='store',
                        help='NLTM hash')
    parser.add_argument('-n',
                        action='store_true',
                        help='Do not resolve names')
    parser.add_argument('-ns',
                        '--nameserver',
                        action='store',
                        help='Alternative name server to use for queries')
    # Todo: match sharphound profiles
    parser.add_argument('--skip-groups',
                        action='store_true',
                        help='Do not query Group memberships via LDAP')
    parser.add_argument('--skip-computers',
                        action='store_true',
                        help='Do not connect to individual computers')
    parser.add_argument('-d',
                        '--domain',
                        action='store',
                        help='Domain')
    parser.add_argument('-v',
                        action='store_true',
                        help='Enable verbose output')

    args = parser.parse_args()

    if args.v is True:
        logger.setLevel(logging.DEBUG)

    if args.kerberos is True:
        logging.debug('Authentication: kerberos')
        kerberize()
        auth = ADAuthentication()
    elif args.username is not None and args.password is not None:
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

    ad = AD(auth=auth, domain=args.domain, nameserver=args.nameserver)

    if args.n is not True:
        logging.debug('Using DNS to retrieve domain information')
        ad.dns_resolve(kerberos=args.kerberos, domain=args.domain)

    bloodhound = BloodHound(ad)
    bloodhound.connect()
    bloodhound.run(skip_groups=args.skip_groups, skip_computers=args.skip_computers)


if __name__ == '__main__':
    main()
