# BloodHound.py
![Python 3 compatible](https://img.shields.io/badge/python-3.x-blue.svg)
![PyPI version](https://img.shields.io/pypi/v/bloodhound.svg)
![License: MIT](https://img.shields.io/pypi/l/bloodhound.svg)

BloodHound.py is a Python based ingestor for [BloodHound](https://github.com/BloodHoundAD/BloodHound), based on [Impacket](https://github.com/CoreSecurity/impacket/).

This fork adds **AD CS (Active Directory Certificate Services) enumeration** with output compatible with **BloodHound CE v6**. ADCS data is collected entirely via LDAP (DC-only, no host connections required) and produces the same JSON node/edge types that SharpHound CE emits, enabling full certificate attack-path analysis in BloodHound.

## ADCS Support

### What is collected

| Output file | BH CE node type | Contents |
|---|---|---|
| `certtemplates.json` | `CertTemplate` | Certificate templates with EKUs, flags, validity periods, schema version, authentication capability, enrollment/write ACLs |
| `enterprisecas.json` | `EnterpriseCA` | Enterprise CAs with enabled templates, hosting computer SID, CA flags, certificate thumbprints |
| `rootcas.json` | `RootCA` | Root CA hierarchy with certificate properties and basic constraints |
| `aiacas.json` | `AIACA` | AIA CA entries with cross-certificate pair handling |
| `ntauthstores.json` | `NTAuthStore` | NTAuth certificate store with all trusted CA thumbprints |

### ADCS edges emitted

| Edge | Applies to | Description |
|---|---|---|
| `Enroll` | CertTemplate, EnterpriseCA | Certificate enrollment permission |
| `AutoEnroll` | CertTemplate | Certificate auto-enrollment permission |
| `ManageCA` | EnterpriseCA | CA administrator right |
| `ManageCertificates` | EnterpriseCA | CA officer right (approve/deny requests) |
| `WritePKIEnrollmentFlag` | CertTemplate | Write `msPKI-Enrollment-Flag` attribute |
| `WritePKINameFlag` | CertTemplate | Write `msPKI-Certificate-Name-Flag` attribute |
| `Owns` | All PKI objects | Object ownership |
| `GenericAll` | All PKI objects | Full control |
| `GenericWrite` | All PKI objects | Generic write access |
| `WriteDacl` | All PKI objects | Modify DACL |
| `WriteOwner` | All PKI objects | Take ownership |
| `AllExtendedRights` | All PKI objects | All extended rights |

### ADCS properties per template

All properties required by BloodHound CE for ESC1-ESC17 attack path analysis are populated:

- `enrolleesuppliessubject`, `subjectaltrequireupn`, `authenticationenabled`
- `ekus`, `effectiveekus`, `certificateapplicationpolicy`, `applicationpolicies`, `issuancepolicies`
- `certificatenameflag`, `enrollmentflag` (human-readable flag strings)
- `requiresmanagerapproval`, `nosecurityextension`, `authorizedsignatures`
- `schemaversion`, `validityperiod`, `renewalperiod`, `displayname`, `oid`

## Installation
* Via pip: `pip bloodhound`
* Via pipx: `pipx install bloodhound`
* By cloning this repository and running `pip install .` from the project directory.

BloodHound.py will add a command line tool `bloodhound-python` to your PATH.

### Optional dependency

If `asn1crypto` is installed, certificate basic constraints are parsed from CA certificates. Without it, basic constraint fields default to safe values. Install with: `pip install asn1crypto`

## Usage
To use the ingestor, at a minimum you will need credentials of the domain you're logging in to. Credentials can be specified as username + password, NT hash or AES keys, or a Kerberos TGT in a ccache file.
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
- *DCOnly* - Runs all collection methods that can be queried from the DC only, no connection to member hosts/servers needed. This is equal to Group,Acl,Trusts,ObjectProps,Container,CertServices
- *Session* - Performs session collection
- *Acl* - Performs ACL collection
- *Trusts* - Performs domain trust enumeration
- *LoggedOn* - Performs privileged Session enumeration (requires local admin on the target)
- *ObjectProps* - Performs Object Properties collection for properties such as LastLogon or PwdLastSet
- *CertServices* - Enumerates AD CS objects: certificate templates, enterprise CAs, root CAs, AIA CAs, and NTAuth stores. DC-only, no host connections required.
- *All* - Runs all methods above (except LoggedOn)
- *Experimental* - Connects to individual hosts to enumerate services and scheduled tasks that may have stored credentials

Multiple collectionmethods should be separated by a comma, for example: `-c Group,LocalAdmin`

### ADCS collection examples

```bash
# Collect only ADCS data (no host connections needed)
bloodhound-python -c CertServices -d domain.local -u user -p password -dc dc01.domain.local

# DC-only collection including ADCS
bloodhound-python -c DCOnly -d domain.local -u user -p password -dc dc01.domain.local

# Full collection including ADCS
bloodhound-python -c All -d domain.local -u user -p password -dc dc01.domain.local

# ADCS with Kerberos authentication
bloodhound-python -c CertServices -d domain.local -u user -k -dc dc01.domain.local

# ADCS with NTLM hash
bloodhound-python -c CertServices -d domain.local -u user --hashes :31d6cfe0d16ae931b73c59d7e0c089c0 -dc dc01.domain.local

# Combine ADCS with specific other methods
bloodhound-python -c Group,Acl,CertServices -d domain.local -u user -p password -dc dc01.domain.local

# Output with zip compression and filename prefix
bloodhound-python -c CertServices -d domain.local -u user -p password -dc dc01.domain.local --zip -op engagement01
```

### Importing into BloodHound CE

1. Run BloodHound.py with a collection method that includes `CertServices`
2. Open BloodHound CE
3. Navigate to **Administration** > **File Ingest**
4. Upload the generated JSON files (or the ZIP if `--zip` was used)
5. Use built-in ADCS queries or write custom Cypher queries for attack path analysis

#### Example Cypher queries

**ESC1 - Enrollee supplies subject with client auth:**
```cypher
MATCH p = (principal)-[:Enroll|GenericAll|AllExtendedRights]->
  (ct:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
WHERE ct.enrolleesuppliessubject = true
  AND ct.authenticationenabled = true
  AND ct.requiresmanagerapproval = false
RETURN p
```

**ESC4 - Dangerous template ACL permissions:**
```cypher
MATCH p = (principal)-[:WriteDacl|WriteOwner|GenericWrite|GenericAll|WritePKIEnrollmentFlag|WritePKINameFlag]->
  (ct:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
WHERE NOT principal.objectid ENDS WITH '-512'
  AND NOT principal.objectid ENDS WITH '-519'
RETURN p
```

You can override some of the automatic detection options, such as the hostname of the primary Domain Controller if you want to use a different Domain Controller with `-dc`, or specify your own Global Catalog with `-gc`.

## Limitations
BloodHound.py currently has the following limitations:
- Supports most, but not all BloodHound (SharpHound) features. Currently GPO local groups are not supported, all other collection methods are implemented.
- ADCS collection is DC-only via LDAP. CA registry data (CASecurity, enrollment agent restrictions, UserSpecifiesSAN flag) requires host access and is not collected. These fields are present in the JSON output with `Collected: false` so BloodHound CE handles them gracefully. For full CA registry enumeration, complement with SharpHound or Certipy.

## Docker usage
1. Build container
```docker build -t bloodhound .```
2. Run container
```docker run -v ${PWD}:/bloodhound-data -it bloodhound```
After that you can run `bloodhound-python` inside the container, all data will be stored in the path from where you start the container.

## Credits
BloodHound.py was originally written by Dirk-jan Mollema, Edwin van Vliet and Matthijs Gielen from [Fox-IT (NCC Group)](https://fox-it.com/). BloodHound.py is currently maintained by Dirk-jan Mollema from [Outsider Security](https://outsidersecurity.nl). The implementation and data model is based on the original tool from [SpecterOps](https://specterops.io). Many thanks to everyone who contributed by testing, submitting issues and pull requests over the years.

ADCS enumeration module by [Whispergate](https://github.com/Whispergate), integrating certificate attack path data derived from research by [Certipy](https://github.com/ly4k/Certipy) (Oliver Lyak) and [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) (Will Schroeder & Lee Christensen).
