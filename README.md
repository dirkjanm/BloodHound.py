# BloodHound.py
![Python 3 compatible](https://img.shields.io/badge/python-3.x-blue.svg)
![PyPI version](https://img.shields.io/pypi/v/bloodhound.svg)
![License: MIT](https://img.shields.io/pypi/l/bloodhound.svg)

BloodHound.py is a Python based ingestor for [BloodHound](https://github.com/BloodHoundAD/BloodHound), based on [Impacket](https://github.com/CoreSecurity/impacket/).

This version of BloodHound.py is **only compatible with BloodHound 4.2 and 4.3**. For BloodHound CE, check out the [bloodhound-ce branch](https://github.com/dirkjanm/BloodHound.py/tree/bloodhound-ce)

## Limitations
BloodHound.py currently has the following limitations:
- Supports most, but not all BloodHound (SharpHound) features. Currently GPO local groups are not supported, all other collection methods are implemented.

## Installation and usage
You can install the ingestor via pip with `pip install bloodhound`, or by cloning this repository and running `pip install .` from the project directory.
BloodHound.py requires `impacket`, `ldap3` and `dnspython` to function.

The installation will add a command line tool `bloodhound-python` to your PATH.

To use the ingestor, at a minimum you will need credentials of the domain you're logging in to.
You will need to specify the `-u` option with a username of this domain (or `username@domain` for a user in a trusted domain). If you have your DNS set up properly and the AD domain is in your DNS search list, then BloodHound.py will automatically detect the domain for you. If not, you have to specify it manually with the `-d` option.

By default BloodHound.py will query LDAP and the individual computers of the domain to enumerate users, computers, groups, trusts, sessions and local admins. 
If you want to restrict collection, specify the `--collectionmethod` parameter, which supports the following options (similar to SharpHound):
- *Default* - Performs group membership collection, domain trust collection, local admin collection, and session collection
- *Group* - Performs group membership collection
- *LocalAdmin* - Performs local admin collection
- *RDP* - Performs Remote Desktop Users collection
- *DCOM* - Performs Distributed COM Users collection
- *Container* - Performs container collection (GPO/Organizational Units/Default containers)
- *PSRemote* - Performs Remote Management (PS Remoting) Users collection
- *DCOnly* - Runs all collection methods that can be queried from the DC only, no connection to member hosts/servers needed. This is equal to Group,Acl,Trusts,ObjectProps,Container
- *Session* - Performs session collection
- *Acl* - Performs ACL collection
- *Trusts* - Performs domain trust enumeration
- *LoggedOn* - Performs privileged Session enumeration (requires local admin on the target)
- *ObjectProps* - Performs Object Properties collection for properties such as LastLogon or PwdLastSet
- *All* - Runs all methods above, except LoggedOn
- *Experimental* - Connects to individual hosts to enumerate services and scheduled tasks that may have stored credentials

Multiple collectionmethods should be separated by a comma, for example: `-c Group,LocalAdmin`

You can override some of the automatic detection options, such as the hostname of the primary Domain Controller if you want to use a different Domain Controller with `-dc`, or specify your own Global Catalog with `-gc`.

## Docker usage
1. Build container  
```docker build -t bloodhound .```  
2. Run container  
```docker run -v ${PWD}:/bloodhound-data -it bloodhound```  
After that you can run `bloodhound-python` inside the container, all data will be stored in the path from where you start the container.

## Credits
BloodHound.py was originally written by Dirk-jan Mollema, Edwin van Vliet and Matthijs Gielen from [Fox-IT (NCC Group)](https://fox-it.com/). BloodHound.py is currently maintained by Dirk-jan Mollema from [Outsider Security](https://outsidersecurity.nl). The implementation and data model is based on the original tool from [SpecterOps](https://specterops.io). Many thanks to everyone who contributed by testing, submitting issues and pull requests over the years.
