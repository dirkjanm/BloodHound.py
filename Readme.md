# BloodHound.py
![Python 2.7](https://img.shields.io/badge/python-2.7.x-blue.svg)
![PyPI version](https://img.shields.io/pypi/v/bloodhound.svg)
![License: MIT](https://img.shields.io/pypi/l/bloodhound.svg)

BloodHound.py is a Python based ingestor for [BloodHound](https://github.com/BloodHoundAD/BloodHound), based on [Impacket](https://github.com/CoreSecurity/impacket/).

This tool is currently in Beta and should not be considered feature-complete or fully stable.

## Limitations
BloodHound.py currently has the following limitations:
- Currently only single domain compatible (this affects mostly user sessions). This includes logging in cross-domain.
- Only supports default BloodHound (SharpHound) features, so only Groups, Admins and Sessions. (trusts still need to be added)
- Name, command line parameters and features may change in the future
- Kerberos support is mostly untested
- The script is currently single-threaded

## Installation and usage
You can install the ingestor via pip with `pip install bloodhound`, or by cloning this repository and running `python setup.py install`, or with `pip install .`.
BloodHound.py requires `impacket` and `dnspython` to function.

The installation will add a command line tool `bloodhound-python` to your PATH.

To use the ingestor, at a minimum you will need credentials of the domain you're logging in to.
You will need to specify the `-u` option with a username of this domain. If you have your DNS set up properly and the AD domain is in your DNS search list, then BloodHound.py will automatically detect the domain for you. If not, you have to specify it manually with the `-d` option.

By default BloodHound.py will query LDAP and the individual computers of the domain to enumerate users, computers, groups, sessions and local admins. To disable some checks, see the options.
