####################
#
# Copyright (c) 2026 Whispergate
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

"""
ADCS (Active Directory Certificate Services) enumeration module for BloodHound.py.

Enumerates PKI objects from AD and produces BloodHound CE v6 compatible JSON files:
  - certtemplates.json
  - enterprisecas.json
  - rootcas.json
  - aiacas.json
  - ntauthstores.json
"""

import logging
import codecs
import json
import struct
import hashlib
import calendar
from io import BytesIO

from impacket.uuid import string_to_bin

from bloodhound.ad.utils import ADUtils, AceResolver
from bloodhound.enumeration.acls import (
    SecurityDescriptor, ACE, ACCESS_MASK, ACCESS_ALLOWED_OBJECT_ACE,
    build_relation,
)

# Try to import asn1crypto for X.509 parsing (basic constraints)
try:
    from asn1crypto import x509 as asn1_x509
    HAS_ASN1CRYPTO = True
except ImportError:
    HAS_ASN1CRYPTO = False

# ---------------------------------------------------------------------------
# ADCS-specific extended right GUIDs
# ---------------------------------------------------------------------------
ADCS_EXTRIGHTS = {
    "Enroll": string_to_bin("0e10c968-78fb-11d2-90d4-00c04f79dc55"),
    "AutoEnroll": string_to_bin("a05b8cc2-17bc-4802-a710-e7c15ab866a2"),
}

# Property GUIDs for ADCS write-property checks
ADCS_PROPERTY_GUIDS = {
    "msPKI-Enrollment-Flag": string_to_bin("d15ef7d8-f226-46db-ae79-b34e560bd12c"),
    "msPKI-Certificate-Name-Flag": string_to_bin("ea1dddc4-60ff-416e-8cc0-17cee534bce7"),
}

# ---------------------------------------------------------------------------
# Certificate Name Flag bits
# ---------------------------------------------------------------------------
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT            = 0x00000001
CT_FLAG_ADD_EMAIL                            = 0x00000002
CT_FLAG_ADD_OBJ_GUID                        = 0x00000004
CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008
CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS       = 0x00400000
CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID   = 0x01000000
CT_FLAG_SUBJECT_ALT_REQUIRE_UPN              = 0x02000000
CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL            = 0x04000000
CT_FLAG_SUBJECT_ALT_REQUIRE_DNS              = 0x08000000
CT_FLAG_SUBJECT_ALT_REQUIRE_SPN              = 0x00000800
CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN            = 0x10000000
CT_FLAG_SUBJECT_REQUIRE_EMAIL                = 0x20000000
CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME          = 0x40000000
CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH       = 0x80000000

CERT_NAME_FLAGS = {
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: "ENROLLEE_SUPPLIES_SUBJECT",
    CT_FLAG_ADD_EMAIL: "ADD_EMAIL",
    CT_FLAG_ADD_OBJ_GUID: "ADD_OBJ_GUID",
    CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME: "OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME",
    CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS: "SUBJECT_ALT_REQUIRE_DOMAIN_DNS",
    CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID: "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID",
    CT_FLAG_SUBJECT_ALT_REQUIRE_UPN: "SUBJECT_ALT_REQUIRE_UPN",
    CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL: "SUBJECT_ALT_REQUIRE_EMAIL",
    CT_FLAG_SUBJECT_ALT_REQUIRE_DNS: "SUBJECT_ALT_REQUIRE_DNS",
    CT_FLAG_SUBJECT_ALT_REQUIRE_SPN: "SUBJECT_ALT_REQUIRE_SPN",
    CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN: "SUBJECT_REQUIRE_DNS_AS_CN",
    CT_FLAG_SUBJECT_REQUIRE_EMAIL: "SUBJECT_REQUIRE_EMAIL",
    CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME: "SUBJECT_REQUIRE_COMMON_NAME",
    CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH: "SUBJECT_REQUIRE_DIRECTORY_PATH",
}

# ---------------------------------------------------------------------------
# Enrollment Flag bits
# ---------------------------------------------------------------------------
CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS            = 0x00000002
CT_FLAG_PUBLISH_TO_KRA_CONTAINER     = 0x00000004
CT_FLAG_PUBLISH_TO_DS                = 0x00000008
CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010
CT_FLAG_AUTO_ENROLLMENT              = 0x00000020
CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040
CT_FLAG_NO_SECURITY_EXTENSION        = 0x00080000

ENROLLMENT_FLAGS = {
    CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS: "INCLUDE_SYMMETRIC_ALGORITHMS",
    CT_FLAG_PEND_ALL_REQUESTS: "PEND_ALL_REQUESTS",
    CT_FLAG_PUBLISH_TO_KRA_CONTAINER: "PUBLISH_TO_KRA_CONTAINER",
    CT_FLAG_PUBLISH_TO_DS: "PUBLISH_TO_DS",
    CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE: "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE",
    CT_FLAG_AUTO_ENROLLMENT: "AUTO_ENROLLMENT",
    CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT: "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT",
    CT_FLAG_NO_SECURITY_EXTENSION: "NO_SECURITY_EXTENSION",
}

# ---------------------------------------------------------------------------
# Enterprise CA flags
# ---------------------------------------------------------------------------
CA_FLAG_SUPPORTS_NT_AUTHENTICATION   = 0x00000002
CA_FLAG_CA_SERVERTYPE_ADVANCED       = 0x00000001
CA_FLAG_NO_TEMPLATE_SUPPORT          = 0x00000004

CA_FLAGS = {
    CA_FLAG_CA_SERVERTYPE_ADVANCED: "CA_SERVERTYPE_ADVANCED",
    CA_FLAG_SUPPORTS_NT_AUTHENTICATION: "SUPPORTS_NT_AUTHENTICATION",
    CA_FLAG_NO_TEMPLATE_SUPPORT: "NO_TEMPLATE_SUPPORT",
}

# ---------------------------------------------------------------------------
# Authentication EKU OIDs
# ---------------------------------------------------------------------------
AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",       # Client Authentication
    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
    "1.3.6.1.5.2.3.4",         # PKINIT Client Auth
    "2.5.29.37.0",              # Any Purpose
}


# ===========================================================================
# Helper functions
# ===========================================================================

def _flags_to_str(value, flag_map):
    """Convert an integer bitmask to a comma-separated flag names string."""
    if not isinstance(value, int):
        try:
            value = int(value)
        except (TypeError, ValueError):
            return "NONE"
    names = []
    for bit, name in sorted(flag_map.items()):
        if value & bit:
            names.append(name)
    return ", ".join(names) if names else "NONE"


def _filetime_to_span(raw):
    """
    Convert a pKIExpirationPeriod / pKIOverlapPeriod value (8-byte LE FILETIME
    representing a negative 100-ns interval) into a human-readable string.
    """
    if isinstance(raw, bytes) and len(raw) == 8:
        low, high = struct.unpack('<Ii', raw[:4] + raw[4:])
        total = abs((high << 32) | (low & 0xFFFFFFFF))
        seconds = total // 10_000_000
        if seconds == 0:
            return "0 seconds"
        if seconds >= 31536000 and seconds % 31536000 == 0:
            n = seconds // 31536000
            return "%d year%s" % (n, "s" if n > 1 else "")
        if seconds >= 604800 and seconds % 604800 == 0:
            n = seconds // 604800
            return "%d week%s" % (n, "s" if n > 1 else "")
        if seconds >= 86400 and seconds % 86400 == 0:
            n = seconds // 86400
            return "%d day%s" % (n, "s" if n > 1 else "")
        if seconds >= 3600 and seconds % 3600 == 0:
            n = seconds // 3600
            return "%d hour%s" % (n, "s" if n > 1 else "")
        return "%d second%s" % (seconds, "s" if seconds > 1 else "")
    return "0 seconds"


def _format_guid(raw_guid):
    """Format a raw objectGUID (from ldap3) to uppercase no-braces string."""
    if isinstance(raw_guid, str):
        return raw_guid.strip("{}").upper()
    return ""


def _cert_thumbprint(der_bytes):
    """Return uppercase hex SHA-1 thumbprint for a DER-encoded certificate."""
    if isinstance(der_bytes, bytes) and len(der_bytes) > 0:
        return hashlib.sha1(der_bytes).hexdigest().upper()
    return ""


def _parse_basic_constraints(der_bytes):
    """
    Parse basic constraints from a DER certificate.
    Returns (has_basic_constraints: bool, path_length: int).
    """
    if not HAS_ASN1CRYPTO or not isinstance(der_bytes, bytes) or len(der_bytes) == 0:
        return False, 0
    try:
        cert = asn1_x509.Certificate.load(der_bytes)
        for ext in cert['tbs_certificate']['extensions']:
            if ext['extn_id'].dotted == '2.5.29.19':  # Basic Constraints
                bc = ext['extn_value'].parsed
                has_bc = True
                pl = bc['path_len_constraint'].native
                return has_bc, pl if pl is not None else 0
    except Exception:
        pass
    return False, 0


def _whencreated_to_epoch(value):
    """Convert a whencreated datetime to epoch int."""
    if isinstance(value, int):
        return value
    if value is None:
        return 0
    try:
        return int(calendar.timegm(value.timetuple()))
    except Exception:
        return 0


# ===========================================================================
# ADCS ACL parsing
# ===========================================================================

def parse_certtemplate_acl(entry, acl):
    """
    Parse ACL for a certificate template object.
    Returns (entry_with_IsACLProtected, list_of_ace_relations).
    """
    if not acl:
        return entry, []

    sd = SecurityDescriptor(BytesIO(acl))
    entry['IsACLProtected'] = sd.has_control(sd.PD)
    relations = []

    ignoresids = ["S-1-3-0", "S-1-5-18", "S-1-5-10"]

    # Owner
    osid = str(sd.owner_sid)
    if osid not in ignoresids:
        relations.append(build_relation(osid, 'Owns', inherited=False))

    for ace_obj in sd.dacl.aces:
        if ace_obj.ace.AceType not in (0x00, 0x05):
            continue
        if ace_obj.acedata is None:
            continue

        sid = str(ace_obj.acedata.sid)
        if sid in ignoresids:
            continue

        is_inherited = ace_obj.has_flag(ACE.INHERITED_ACE)

        if ace_obj.ace.AceType == 0x05:
            # ACCESS_ALLOWED_OBJECT_ACE
            if not ace_obj.has_flag(ACE.INHERITED_ACE) and ace_obj.has_flag(ACE.INHERIT_ONLY_ACE):
                continue

            mask = ace_obj.acedata.mask

            # --- Generic access ---
            if mask.has_priv(ACCESS_MASK.GENERIC_ALL):
                if ace_obj.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                    # Check if it applies to a specific object type we don't care about
                    pass
                relations.append(build_relation(sid, 'GenericAll', inherited=is_inherited))
                continue

            if mask.has_priv(ACCESS_MASK.GENERIC_WRITE):
                relations.append(build_relation(sid, 'GenericWrite', inherited=is_inherited))

            if mask.has_priv(ACCESS_MASK.WRITE_DACL):
                relations.append(build_relation(sid, 'WriteDacl', inherited=is_inherited))

            if mask.has_priv(ACCESS_MASK.WRITE_OWNER):
                relations.append(build_relation(sid, 'WriteOwner', inherited=is_inherited))

            # --- Property writes ---
            if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP):
                if not ace_obj.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                    relations.append(build_relation(sid, 'GenericWrite', inherited=is_inherited))
                else:
                    obj_type = ace_obj.acedata.data.ObjectType
                    if obj_type == ADCS_PROPERTY_GUIDS["msPKI-Enrollment-Flag"]:
                        relations.append(build_relation(sid, 'WritePKIEnrollmentFlag', inherited=is_inherited))
                    if obj_type == ADCS_PROPERTY_GUIDS["msPKI-Certificate-Name-Flag"]:
                        relations.append(build_relation(sid, 'WritePKINameFlag', inherited=is_inherited))

            # --- Extended rights (Enroll / AutoEnroll / AllExtendedRights) ---
            if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS):
                if not ace_obj.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                    relations.append(build_relation(sid, 'AllExtendedRights', inherited=is_inherited))
                else:
                    obj_type = ace_obj.acedata.data.ObjectType
                    if obj_type == ADCS_EXTRIGHTS["Enroll"]:
                        relations.append(build_relation(sid, 'Enroll', inherited=is_inherited))
                    if obj_type == ADCS_EXTRIGHTS["AutoEnroll"]:
                        relations.append(build_relation(sid, 'AutoEnroll', inherited=is_inherited))

        elif ace_obj.ace.AceType == 0x00:
            # ACCESS_ALLOWED_ACE (no object type)
            if not ace_obj.has_flag(ACE.INHERITED_ACE) and ace_obj.has_flag(ACE.INHERIT_ONLY_ACE):
                continue

            mask = ace_obj.acedata.mask

            if mask.has_priv(ACCESS_MASK.GENERIC_ALL):
                relations.append(build_relation(sid, 'GenericAll', inherited=is_inherited))
                continue

            if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP):
                relations.append(build_relation(sid, 'GenericWrite', inherited=is_inherited))

            if mask.has_priv(ACCESS_MASK.WRITE_OWNER):
                relations.append(build_relation(sid, 'WriteOwner', inherited=is_inherited))

            if mask.has_priv(ACCESS_MASK.WRITE_DACL):
                relations.append(build_relation(sid, 'WriteDacl', inherited=is_inherited))

            if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS):
                relations.append(build_relation(sid, 'AllExtendedRights', inherited=is_inherited))

    return entry, relations


def parse_pki_object_acl(entry, acl):
    """
    Parse ACL for PKI objects (Enterprise CAs, Root CAs, AIA CAs, NTAuth stores).
    Extracts: Owns, GenericAll, GenericWrite, WriteDacl, WriteOwner, AllExtendedRights,
    Enroll, ManageCA, ManageCertificates.
    """
    if not acl:
        return entry, []

    sd = SecurityDescriptor(BytesIO(acl))
    entry['IsACLProtected'] = sd.has_control(sd.PD)
    relations = []

    ignoresids = ["S-1-3-0", "S-1-5-18", "S-1-5-10"]

    osid = str(sd.owner_sid)
    if osid not in ignoresids:
        relations.append(build_relation(osid, 'Owns', inherited=False))

    for ace_obj in sd.dacl.aces:
        if ace_obj.ace.AceType not in (0x00, 0x05):
            continue
        if ace_obj.acedata is None:
            continue

        sid = str(ace_obj.acedata.sid)
        if sid in ignoresids:
            continue

        is_inherited = ace_obj.has_flag(ACE.INHERITED_ACE)

        if ace_obj.ace.AceType == 0x05:
            if not ace_obj.has_flag(ACE.INHERITED_ACE) and ace_obj.has_flag(ACE.INHERIT_ONLY_ACE):
                continue

            mask = ace_obj.acedata.mask

            if mask.has_priv(ACCESS_MASK.GENERIC_ALL):
                relations.append(build_relation(sid, 'GenericAll', inherited=is_inherited))
                continue

            if mask.has_priv(ACCESS_MASK.GENERIC_WRITE):
                relations.append(build_relation(sid, 'GenericWrite', inherited=is_inherited))

            if mask.has_priv(ACCESS_MASK.WRITE_DACL):
                relations.append(build_relation(sid, 'WriteDacl', inherited=is_inherited))

            if mask.has_priv(ACCESS_MASK.WRITE_OWNER):
                relations.append(build_relation(sid, 'WriteOwner', inherited=is_inherited))

            if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP):
                if not ace_obj.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                    relations.append(build_relation(sid, 'GenericWrite', inherited=is_inherited))

            if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS):
                if not ace_obj.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                    relations.append(build_relation(sid, 'AllExtendedRights', inherited=is_inherited))
                else:
                    obj_type = ace_obj.acedata.data.ObjectType
                    if obj_type == ADCS_EXTRIGHTS["Enroll"]:
                        relations.append(build_relation(sid, 'Enroll', inherited=is_inherited))

        elif ace_obj.ace.AceType == 0x00:
            if not ace_obj.has_flag(ACE.INHERITED_ACE) and ace_obj.has_flag(ACE.INHERIT_ONLY_ACE):
                continue

            mask = ace_obj.acedata.mask

            if mask.has_priv(ACCESS_MASK.GENERIC_ALL):
                relations.append(build_relation(sid, 'GenericAll', inherited=is_inherited))
                continue

            if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP):
                relations.append(build_relation(sid, 'GenericWrite', inherited=is_inherited))

            if mask.has_priv(ACCESS_MASK.WRITE_OWNER):
                relations.append(build_relation(sid, 'WriteOwner', inherited=is_inherited))

            if mask.has_priv(ACCESS_MASK.WRITE_DACL):
                relations.append(build_relation(sid, 'WriteDacl', inherited=is_inherited))

            if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS):
                relations.append(build_relation(sid, 'AllExtendedRights', inherited=is_inherited))

    return entry, relations


# ===========================================================================
# Main enumerator class
# ===========================================================================

class ADCSEnumerator(object):
    """
    Enumerates AD Certificate Services objects via LDAP and writes
    BloodHound CE v6 compatible JSON output files.
    """

    def __init__(self, addomain, addc):
        self.addomain = addomain
        self.addc = addc

    # -----------------------------------------------------------------------
    # Public entry point
    # -----------------------------------------------------------------------

    def enumerate_adcs(self, timestamp="", fileNamePrefix="", collect=None):
        """
        Main method: enumerate all ADCS objects and write JSON files.

        Args:
            timestamp:      Timestamp string prefix for output files.
            fileNamePrefix: Optional filename prefix.
            collect:        Set/list of collection methods (unused for now — always collects ADCS).
        """
        logging.info("Starting ADCS enumeration")

        config_nc = self._get_config_nc()
        if not config_nc:
            logging.error("Could not determine configurationNamingContext. Aborting ADCS enumeration.")
            return

        pks_base = "CN=Public Key Services,CN=Services,%s" % config_nc

        # Build an ACE resolver for SID → principal resolution
        resolver = AceResolver(self.addomain, self.addomain.objectresolver)

        # Collect container GUIDs we'll need for ContainedBy
        container_guid_cache = {}

        # --- Certificate Templates ---
        self._enumerate_certtemplates(pks_base, resolver, container_guid_cache, timestamp, fileNamePrefix)

        # --- Enterprise CAs ---
        self._enumerate_enterprisecas(pks_base, resolver, container_guid_cache, timestamp, fileNamePrefix)

        # --- Root CAs ---
        self._enumerate_rootcas(pks_base, resolver, container_guid_cache, timestamp, fileNamePrefix)

        # --- AIA CAs ---
        self._enumerate_aiacas(pks_base, resolver, container_guid_cache, timestamp, fileNamePrefix)

        # --- NTAuth Store ---
        self._enumerate_ntauthstores(pks_base, resolver, container_guid_cache, timestamp, fileNamePrefix)

        logging.info("ADCS enumeration completed")

    # -----------------------------------------------------------------------
    # Config NC
    # -----------------------------------------------------------------------

    def _get_config_nc(self):
        try:
            return self.addc.ldap.server.info.other['configurationNamingContext'][0]
        except (KeyError, IndexError, TypeError, AttributeError):
            return None

    # -----------------------------------------------------------------------
    # Container GUID resolution
    # -----------------------------------------------------------------------

    def _get_container_guid(self, container_dn, cache):
        """Resolve the objectGUID for a container DN, with caching."""
        dn_upper = container_dn.upper()
        if dn_upper in cache:
            return cache[dn_upper]

        entry = self.addc.ldap_get_single(container_dn, attributes=['objectGUID'])
        if entry:
            guid = _format_guid(ADUtils.get_entry_property(entry, 'objectGUID', ''))
        else:
            guid = ""
        cache[dn_upper] = guid
        return guid

    def _build_contained_by(self, child_dn, cache):
        """Build the ContainedBy dict for an object given its DN."""
        parts = child_dn.split(',', 1)
        if len(parts) < 2:
            return {"ObjectIdentifier": "", "ObjectType": "Container"}
        parent_dn = parts[1]
        guid = self._get_container_guid(parent_dn, cache)
        return {"ObjectIdentifier": guid, "ObjectType": "Container"}

    # -----------------------------------------------------------------------
    # Shared helpers
    # -----------------------------------------------------------------------

    def _get_domain_name(self):
        return self.addomain.domain.upper()

    def _get_domain_sid(self):
        try:
            return self.addomain.domain_object.sid
        except AttributeError:
            return ""

    def _make_filename(self, base, timestamp, prefix):
        if prefix:
            return "%s_%s%s" % (prefix, timestamp, base)
        return "%s%s" % (timestamp, base)

    def _get_indent(self):
        if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
            return 1
        return None

    def _write_json(self, filename, data_list, meta_type):
        """Write a BloodHound CE v6 JSON file."""
        datastruct = {
            "data": data_list,
            "meta": {
                "methods": 0,
                "type": meta_type,
                "count": len(data_list),
                "version": 6
            }
        }
        try:
            logging.debug("Opening file for writing: %s", filename)
            with codecs.open(filename, 'w', 'utf-8') as fh:
                json.dump(datastruct, fh, indent=self._get_indent())
        except Exception:
            logging.warning("Could not write file: %s", filename)

    def _get_raw_cert(self, entry):
        """Get raw DER bytes of cACertificate from an entry."""
        raw = ADUtils.get_entry_property(entry, 'cACertificate', default=None, raw=True)
        if raw is None:
            return None
        if isinstance(raw, list):
            return raw[0] if raw else None
        return raw

    def _get_all_raw_certs(self, entry):
        """Get list of all raw DER cACertificate values."""
        raw = ADUtils.get_entry_property(entry, 'cACertificate', default=[], raw=True)
        if not isinstance(raw, list):
            raw = [raw] if raw else []
        return raw

    def _cert_props(self, der_bytes):
        """Return (thumbprint, certname, certchain, hasbasicconstraints, pathlen) for a cert."""
        tp = _cert_thumbprint(der_bytes) if der_bytes else ""
        has_bc, pl = _parse_basic_constraints(der_bytes) if der_bytes else (False, 0)
        return tp, tp, [tp] if tp else [], has_bc, pl

    # -----------------------------------------------------------------------
    # Certificate Templates
    # -----------------------------------------------------------------------

    def _enumerate_certtemplates(self, pks_base, resolver, container_cache, timestamp, prefix):
        search_base = "CN=Certificate Templates,%s" % pks_base
        ldap_filter = "(objectClass=pKICertificateTemplate)"
        attributes = [
            'cn', 'name', 'displayName', 'objectGUID', 'distinguishedName',
            'nTSecurityDescriptor', 'pKIExpirationPeriod', 'pKIOverlapPeriod',
            'msPKI-Enrollment-Flag', 'msPKI-Private-Key-Flag',
            'msPKI-Certificate-Name-Flag', 'msPKI-Certificate-Policy',
            'msPKI-Minimal-Key-Size', 'msPKI-RA-Signature',
            'msPKI-Template-Schema-Version', 'msPKI-RA-Application-Policies',
            'pKIExtendedKeyUsage', 'whencreated', 'description',
            'msPKI-Cert-Template-OID',
        ]

        entries = self.addc.search(
            ldap_filter, attributes,
            search_base=search_base, generator=True, query_sd=True
        )

        domain = self._get_domain_name()
        domain_sid = self._get_domain_sid()
        results = []
        num = 0

        for entry in entries:
            num += 1
            cn = ADUtils.get_entry_property(entry, 'cn', '')
            name = ADUtils.get_entry_property(entry, 'name', cn)
            dn = ADUtils.get_entry_property(entry, 'distinguishedName', '')
            guid = _format_guid(ADUtils.get_entry_property(entry, 'objectGUID', ''))
            display_name = ADUtils.get_entry_property(entry, 'displayName', '')
            description = ADUtils.get_entry_property(entry, 'description', None)
            whencreated = _whencreated_to_epoch(ADUtils.get_entry_property(entry, 'whencreated', 0))
            schema_version = ADUtils.get_entry_property(entry, 'msPKI-Template-Schema-Version', 1)
            oid = ADUtils.get_entry_property(entry, 'msPKI-Cert-Template-OID', '')

            # Flags
            enrollment_flag_raw = ADUtils.get_entry_property(entry, 'msPKI-Enrollment-Flag', 0)
            name_flag_raw = ADUtils.get_entry_property(entry, 'msPKI-Certificate-Name-Flag', 0)
            try:
                enrollment_flag_int = int(enrollment_flag_raw)
            except (TypeError, ValueError):
                enrollment_flag_int = 0
            try:
                name_flag_int = int(name_flag_raw)
            except (TypeError, ValueError):
                name_flag_int = 0

            enrollment_flag_str = _flags_to_str(enrollment_flag_int, ENROLLMENT_FLAGS)
            name_flag_str = _flags_to_str(name_flag_int, CERT_NAME_FLAGS)

            # Requires manager approval
            requires_manager_approval = bool(enrollment_flag_int & CT_FLAG_PEND_ALL_REQUESTS)
            # No security extension
            no_security_extension = bool(enrollment_flag_int & CT_FLAG_NO_SECURITY_EXTENSION)
            # enrolleesuppliessubject
            enrollee_supplies_subject = bool(name_flag_int & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            # subjectaltrequireupn
            subject_alt_require_upn = bool(name_flag_int & CT_FLAG_SUBJECT_ALT_REQUIRE_UPN)

            # RA signature
            ra_signature = ADUtils.get_entry_property(entry, 'msPKI-RA-Signature', 0)
            try:
                ra_signature = int(ra_signature)
            except (TypeError, ValueError):
                ra_signature = 0

            # EKUs
            ekus_raw = ADUtils.get_entry_property(entry, 'pKIExtendedKeyUsage', default=[])
            if not isinstance(ekus_raw, list):
                ekus_raw = [ekus_raw] if ekus_raw else []

            # Certificate application policy
            cert_app_policy = ADUtils.get_entry_property(entry, 'msPKI-Certificate-Policy', default=[])
            if not isinstance(cert_app_policy, list):
                cert_app_policy = [cert_app_policy] if cert_app_policy else []

            # RA application policies
            ra_app_policies = ADUtils.get_entry_property(entry, 'msPKI-RA-Application-Policies', default=[])
            if not isinstance(ra_app_policies, list):
                ra_app_policies = [ra_app_policies] if ra_app_policies else []

            # Effective EKUs (pass through ekus)
            effective_ekus = list(ekus_raw)

            # Authentication enabled
            auth_enabled = len(ekus_raw) == 0 or any(eku in AUTH_EKUS for eku in ekus_raw)

            # Validity / renewal periods (raw bytes)
            validity_raw = ADUtils.get_entry_property(entry, 'pKIExpirationPeriod', default=None, raw=True)
            renewal_raw = ADUtils.get_entry_property(entry, 'pKIOverlapPeriod', default=None, raw=True)
            if isinstance(validity_raw, list):
                validity_raw = validity_raw[0] if validity_raw else None
            if isinstance(renewal_raw, list):
                renewal_raw = renewal_raw[0] if renewal_raw else None

            validity_period = _filetime_to_span(validity_raw) if validity_raw else "0 seconds"
            renewal_period = _filetime_to_span(renewal_raw) if renewal_raw else "0 seconds"

            # Build template entry
            tmpl = {
                "ObjectIdentifier": guid,
                "Properties": {
                    "domain": domain,
                    "name": ("%s@%s" % (name, domain)).upper(),
                    "distinguishedname": dn,
                    "domainsid": domain_sid,
                    "description": description,
                    "whencreated": whencreated,
                    "validityperiod": validity_period,
                    "renewalperiod": renewal_period,
                    "schemaversion": schema_version if isinstance(schema_version, int) else int(schema_version or 1),
                    "displayname": display_name,
                    "oid": oid,
                    "enrollmentflag": enrollment_flag_str,
                    "requiresmanagerapproval": requires_manager_approval,
                    "nosecurityextension": no_security_extension,
                    "certificatenameflag": name_flag_str,
                    "enrolleesuppliessubject": enrollee_supplies_subject,
                    "subjectaltrequireupn": subject_alt_require_upn,
                    "ekus": ekus_raw,
                    "certificateapplicationpolicy": cert_app_policy,
                    "authorizedsignatures": ra_signature,
                    "applicationpolicies": ra_app_policies,
                    "issuancepolicies": [],
                    "effectiveekus": effective_ekus,
                    "authenticationenabled": auth_enabled,
                },
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
                "ContainedBy": self._build_contained_by(dn, container_cache),
            }

            # ACL
            sd_data = ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', default=None, raw=True)
            if isinstance(sd_data, list):
                sd_data = sd_data[0] if sd_data else None
            if sd_data:
                tmpl, aces = parse_certtemplate_acl(tmpl, sd_data)
                tmpl['Aces'] = resolver.resolve_aces(aces)

            results.append(tmpl)

        filename = self._make_filename("certtemplates.json", timestamp, prefix)
        self._write_json(filename, results, "certtemplates")
        logging.info("Found %u certificate templates", num)

    # -----------------------------------------------------------------------
    # Enterprise CAs
    # -----------------------------------------------------------------------

    def _enumerate_enterprisecas(self, pks_base, resolver, container_cache, timestamp, prefix):
        search_base = "CN=Enrollment Services,%s" % pks_base
        ldap_filter = "(objectClass=pKIEnrollmentService)"
        attributes = [
            'cn', 'name', 'objectGUID', 'distinguishedName',
            'nTSecurityDescriptor', 'dNSHostName', 'cACertificateDN',
            'cACertificate', 'certificateTemplates', 'whencreated',
            'description', 'flags',
        ]

        entries = self.addc.search(
            ldap_filter, attributes,
            search_base=search_base, generator=True, query_sd=True
        )

        domain = self._get_domain_name()
        domain_sid = self._get_domain_sid()

        # Pre-fetch cert template GUIDs for EnabledCertTemplates mapping
        tmpl_guid_map = self._get_certtemplate_guid_map(pks_base)

        results = []
        num = 0

        for entry in entries:
            num += 1
            cn = ADUtils.get_entry_property(entry, 'cn', '')
            name = ADUtils.get_entry_property(entry, 'name', cn)
            dn = ADUtils.get_entry_property(entry, 'distinguishedName', '')
            guid = _format_guid(ADUtils.get_entry_property(entry, 'objectGUID', ''))
            description = ADUtils.get_entry_property(entry, 'description', None)
            whencreated = _whencreated_to_epoch(ADUtils.get_entry_property(entry, 'whencreated', 0))
            dns_hostname = ADUtils.get_entry_property(entry, 'dNSHostName', '')
            ca_name = ADUtils.get_entry_property(entry, 'name', cn)
            flags_raw = ADUtils.get_entry_property(entry, 'flags', 0)

            try:
                flags_int = int(flags_raw)
            except (TypeError, ValueError):
                flags_int = 0
            flags_str = _flags_to_str(flags_int, CA_FLAGS)

            # Certificate processing
            der_bytes = self._get_raw_cert(entry)
            thumbprint, certname, certchain, has_bc, bc_pl = self._cert_props(der_bytes)

            # certificateTemplates - list of template CN names
            cert_templates_raw = ADUtils.get_entry_property(entry, 'certificateTemplates', default=[])
            if not isinstance(cert_templates_raw, list):
                cert_templates_raw = [cert_templates_raw] if cert_templates_raw else []

            enabled_templates = []
            for tmpl_cn in cert_templates_raw:
                tmpl_guid = tmpl_guid_map.get(tmpl_cn.lower(), "")
                enabled_templates.append({
                    "ObjectIdentifier": tmpl_guid,
                    "ObjectType": "CertTemplate"
                })

            # Hosting computer SID resolution
            hosting_computer_sid = ""
            if dns_hostname:
                try:
                    hosting_computer_sid = self.addomain.computersidcache.get(dns_hostname.lower())
                except KeyError:
                    logging.debug("Could not resolve hosting computer SID for %s", dns_hostname)

            ca_obj = {
                "ObjectIdentifier": guid,
                "Properties": {
                    "domain": domain,
                    "name": ("%s@%s" % (name, domain)).upper(),
                    "distinguishedname": dn,
                    "domainsid": domain_sid,
                    "description": description,
                    "whencreated": whencreated,
                    "flags": flags_str,
                    "caname": ca_name,
                    "dnshostname": dns_hostname,
                    "certthumbprint": thumbprint,
                    "certname": certname,
                    "certchain": certchain,
                    "hasbasicconstraints": has_bc,
                    "basicconstraintpathlength": bc_pl,
                    "casecuritycollected": False,
                    "enrollmentagentrestrictionscollected": False,
                    "isuserspecifiessanenabledcollected": False,
                },
                "HostingComputer": hosting_computer_sid,
                "CARegistryData": {
                    "CASecurity": {
                        "Data": [],
                        "Collected": False,
                        "FailureReason": None,
                    },
                    "EnrollmentAgentRestrictions": {
                        "Restrictions": [],
                        "Collected": False,
                        "FailureReason": None,
                    },
                    "IsUserSpecifiesSanEnabled": {
                        "Value": False,
                        "Collected": False,
                        "FailureReason": None,
                    },
                },
                "EnabledCertTemplates": enabled_templates,
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
                "ContainedBy": self._build_contained_by(dn, container_cache),
            }

            # ACL
            sd_data = ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', default=None, raw=True)
            if isinstance(sd_data, list):
                sd_data = sd_data[0] if sd_data else None
            if sd_data:
                ca_obj, aces = parse_pki_object_acl(ca_obj, sd_data)
                ca_obj['Aces'] = resolver.resolve_aces(aces)

            results.append(ca_obj)

        filename = self._make_filename("enterprisecas.json", timestamp, prefix)
        self._write_json(filename, results, "enterprisecas")
        logging.info("Found %u Enterprise CAs", num)

    def _get_certtemplate_guid_map(self, pks_base):
        """Build a mapping of lowercase CN → objectGUID for all cert templates."""
        search_base = "CN=Certificate Templates,%s" % pks_base
        entries = self.addc.search(
            "(objectClass=pKICertificateTemplate)",
            ['cn', 'objectGUID'],
            search_base=search_base,
            generator=True
        )
        result = {}
        for entry in entries:
            cn = ADUtils.get_entry_property(entry, 'cn', '')
            guid = _format_guid(ADUtils.get_entry_property(entry, 'objectGUID', ''))
            if cn and guid:
                result[cn.lower()] = guid
        return result

    # -----------------------------------------------------------------------
    # Root CAs
    # -----------------------------------------------------------------------

    def _enumerate_rootcas(self, pks_base, resolver, container_cache, timestamp, prefix):
        search_base = "CN=Certification Authorities,%s" % pks_base
        ldap_filter = "(objectClass=certificationAuthority)"
        attributes = [
            'cn', 'name', 'objectGUID', 'distinguishedName',
            'nTSecurityDescriptor', 'cACertificate', 'whencreated', 'description',
        ]

        entries = self.addc.search(
            ldap_filter, attributes,
            search_base=search_base, generator=True, query_sd=True
        )

        domain = self._get_domain_name()
        domain_sid = self._get_domain_sid()
        results = []
        num = 0

        for entry in entries:
            num += 1
            name = ADUtils.get_entry_property(entry, 'name', ADUtils.get_entry_property(entry, 'cn', ''))
            dn = ADUtils.get_entry_property(entry, 'distinguishedName', '')
            guid = _format_guid(ADUtils.get_entry_property(entry, 'objectGUID', ''))
            description = ADUtils.get_entry_property(entry, 'description', None)
            whencreated = _whencreated_to_epoch(ADUtils.get_entry_property(entry, 'whencreated', 0))

            der_bytes = self._get_raw_cert(entry)
            thumbprint, certname, certchain, has_bc, bc_pl = self._cert_props(der_bytes)

            obj = {
                "ObjectIdentifier": guid,
                "DomainSID": domain_sid,
                "Properties": {
                    "domain": domain,
                    "name": ("%s@%s" % (name, domain)).upper(),
                    "distinguishedname": dn,
                    "domainsid": domain_sid,
                    "description": description,
                    "whencreated": whencreated,
                    "certthumbprint": thumbprint,
                    "certname": certname,
                    "certchain": certchain,
                    "hasbasicconstraints": has_bc,
                    "basicconstraintpathlength": bc_pl,
                },
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
                "ContainedBy": self._build_contained_by(dn, container_cache),
            }

            sd_data = ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', default=None, raw=True)
            if isinstance(sd_data, list):
                sd_data = sd_data[0] if sd_data else None
            if sd_data:
                obj, aces = parse_pki_object_acl(obj, sd_data)
                obj['Aces'] = resolver.resolve_aces(aces)

            results.append(obj)

        filename = self._make_filename("rootcas.json", timestamp, prefix)
        self._write_json(filename, results, "rootcas")
        logging.info("Found %u Root CAs", num)

    # -----------------------------------------------------------------------
    # AIA CAs
    # -----------------------------------------------------------------------

    def _enumerate_aiacas(self, pks_base, resolver, container_cache, timestamp, prefix):
        search_base = "CN=AIA,%s" % pks_base
        ldap_filter = "(objectClass=certificationAuthority)"
        attributes = [
            'cn', 'name', 'objectGUID', 'distinguishedName',
            'nTSecurityDescriptor', 'cACertificate', 'crossCertificatePair',
            'whencreated', 'description',
        ]

        entries = self.addc.search(
            ldap_filter, attributes,
            search_base=search_base, generator=True, query_sd=True
        )

        domain = self._get_domain_name()
        domain_sid = self._get_domain_sid()
        results = []
        num = 0

        for entry in entries:
            num += 1
            name = ADUtils.get_entry_property(entry, 'name', ADUtils.get_entry_property(entry, 'cn', ''))
            dn = ADUtils.get_entry_property(entry, 'distinguishedName', '')
            guid = _format_guid(ADUtils.get_entry_property(entry, 'objectGUID', ''))
            description = ADUtils.get_entry_property(entry, 'description', None)
            whencreated = _whencreated_to_epoch(ADUtils.get_entry_property(entry, 'whencreated', 0))

            der_bytes = self._get_raw_cert(entry)
            thumbprint, certname, certchain, has_bc, bc_pl = self._cert_props(der_bytes)

            # Cross certificate pair
            cross_cert_raw = ADUtils.get_entry_property(entry, 'crossCertificatePair', default=[], raw=True)
            if not isinstance(cross_cert_raw, list):
                cross_cert_raw = [cross_cert_raw] if cross_cert_raw else []
            has_cross = len(cross_cert_raw) > 0
            # Convert cross certs to thumbprints
            cross_cert_thumbprints = []
            for cc in cross_cert_raw:
                if isinstance(cc, bytes) and len(cc) > 0:
                    cross_cert_thumbprints.append(_cert_thumbprint(cc))

            obj = {
                "ObjectIdentifier": guid,
                "Properties": {
                    "domain": domain,
                    "name": ("%s@%s" % (name, domain)).upper(),
                    "distinguishedname": dn,
                    "domainsid": domain_sid,
                    "description": description,
                    "whencreated": whencreated,
                    "crosscertificatepair": cross_cert_thumbprints,
                    "hascrosscertificatepair": has_cross,
                    "certthumbprint": thumbprint,
                    "certname": certname,
                    "certchain": certchain,
                    "hasbasicconstraints": has_bc,
                    "basicconstraintpathlength": bc_pl,
                },
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
                "ContainedBy": self._build_contained_by(dn, container_cache),
            }

            sd_data = ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', default=None, raw=True)
            if isinstance(sd_data, list):
                sd_data = sd_data[0] if sd_data else None
            if sd_data:
                obj, aces = parse_pki_object_acl(obj, sd_data)
                obj['Aces'] = resolver.resolve_aces(aces)

            results.append(obj)

        filename = self._make_filename("aiacas.json", timestamp, prefix)
        self._write_json(filename, results, "aiacas")
        logging.info("Found %u AIA CAs", num)

    # -----------------------------------------------------------------------
    # NTAuth Store
    # -----------------------------------------------------------------------

    def _enumerate_ntauthstores(self, pks_base, resolver, container_cache, timestamp, prefix):
        search_base = pks_base
        ldap_filter = "(cn=NTAuthCertificates)"
        attributes = [
            'cn', 'objectGUID', 'distinguishedName',
            'nTSecurityDescriptor', 'cACertificate', 'whencreated', 'description',
        ]

        entries = self.addc.search(
            ldap_filter, attributes,
            search_base=search_base, generator=True, query_sd=True
        )

        domain = self._get_domain_name()
        domain_sid = self._get_domain_sid()
        results = []
        num = 0

        for entry in entries:
            num += 1
            dn = ADUtils.get_entry_property(entry, 'distinguishedName', '')
            guid = _format_guid(ADUtils.get_entry_property(entry, 'objectGUID', ''))
            description = ADUtils.get_entry_property(entry, 'description', None)
            whencreated = _whencreated_to_epoch(ADUtils.get_entry_property(entry, 'whencreated', 0))

            # NTAuth store has multiple cACertificate values → collect all thumbprints
            all_certs = self._get_all_raw_certs(entry)
            cert_thumbprints = []
            for cert_der in all_certs:
                tp = _cert_thumbprint(cert_der)
                if tp:
                    cert_thumbprints.append(tp)

            obj = {
                "ObjectIdentifier": guid,
                "DomainSID": domain_sid,
                "Properties": {
                    "domain": domain,
                    "name": ("NTAUTHCERTIFICATES@%s" % domain).upper(),
                    "distinguishedname": dn,
                    "domainsid": domain_sid,
                    "certthumbprints": cert_thumbprints,
                    "description": description,
                    "whencreated": whencreated,
                },
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
                "ContainedBy": self._build_contained_by(dn, container_cache),
            }

            sd_data = ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', default=None, raw=True)
            if isinstance(sd_data, list):
                sd_data = sd_data[0] if sd_data else None
            if sd_data:
                obj, aces = parse_pki_object_acl(obj, sd_data)
                obj['Aces'] = resolver.resolve_aces(aces)

            results.append(obj)

        filename = self._make_filename("ntauthstores.json", timestamp, prefix)
        self._write_json(filename, results, "ntauthstores")
        logging.info("Found %u NTAuth stores", num)
