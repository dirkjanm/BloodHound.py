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

# Built-in imports
import datetime
import logging
import os
import traceback
from binascii import unhexlify
import sys

# Third party library imports
from ldap3 import Server, Connection, NTLM, ALL, SASL, KERBEROS, IP_V4_PREFERRED
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED
from ldap3.operation.bind import bind_operation
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal, KerberosTime, Ticket
from pyasn1.codec.der import decoder, encoder
from impacket.krb5.asn1 import (
    AP_REQ,
    AS_REP,
    TGS_REQ,
    Authenticator,
    TGS_REP,
    seq_set,
    seq_set_iter,
    PA_FOR_USER_ENC,
    Ticket as TicketAsn1,
    EncTGSRepPart,
)
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, sendReceive

from pyasn1.type.univ import noValue
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

# Local library imports
from bloodhound.ad.utils import CollectionException

"""
Active Directory authentication helper
"""


class ADAuthentication(object):
    def __init__(
        self,
        username: str = "",
        password: str = "",
        domain: str = "",
        lm_hash: str = "",
        nt_hash: str = "",
        aeskey: str = "",
        kdc=None,
        auth_method="auto",
    ):
        if not domain:
            raise ValueError("Domain must be specified and cannot be empty.")

        self.domain = domain.lower()
        self.userdomain = self.domain

        self.username = username.lower() if username else ""
        if "@" in self.username:
            self.username, self.userdomain = self.username.rsplit("@", 1)

        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.aeskey = aeskey
        self.kdc = kdc
        self.userdomain_kdc = self.kdc or self.domain
        self.auth_method = auth_method
        self.tgt = None
        # Log all relevant information at debug level
        logging.debug(f"Initializing ADAuthentication with parameters:")
        logging.debug(f"\tUsername: {self.username}")
        logging.debug(f"\tDomain: {self.domain}")
        logging.debug(f"\tUser domain: {self.userdomain}")
        logging.debug(f"\tPassword: {self.password}")
        logging.debug(f"\tLM Hash: {self.lm_hash}")
        logging.debug(f"\tNT Hash: {self.nt_hash}")
        logging.debug(f"\tAES Key: {self.aeskey}")
        logging.debug(f"\tKDC: {self.kdc if self.kdc else 'Default KDC'}")
        logging.debug(f"\tUser Domain KDC: {self.userdomain_kdc}")
        logging.debug(f"\tAuthentication Method: {self.auth_method}")

    def set_aeskey(self, aeskey):
        self.aeskey = aeskey

    def set_kdc(self, kdc):
        # Set KDC
        self.kdc = kdc
        if self.userdomain == self.domain:
            # Also set it for user domain if this is equal
            self.userdomain_kdc = kdc

    def getLDAPConnection(
        self,
        hostname="",
        ip_address="",
        base_dn="",
        protocol="ldaps",
        use_global_catalog=False,
    ):
        # Log incoming parameters to help with debugging
        logging.debug(f"Initializing LDAP Connection with the following parameters:")
        logging.debug(f"\tHostname: {hostname}")
        logging.debug(f"\tIP Address: {ip_address}")
        logging.debug(f"\tBase DN: {base_dn}")
        logging.debug(f"\tProtocol: {protocol}")
        logging.debug(f"\tUse Global Catalog: {use_global_catalog}")

        # Directly use the IP address for the server URL
        port = (
            3269
            if use_global_catalog and protocol == "ldaps"
            else 3268 if use_global_catalog else 636 if protocol == "ldaps" else 389
        )
        server_url = f"{protocol}://{ip_address}:{port}"

        logging.debug(f"Server url: {server_url}")

        server = Server(server_url, get_info=ALL, mode=IP_V4_PREFERRED)

        ldap_username = f"{self.userdomain}\\{self.username}"
        ldap_password = (
            f"{self.lm_hash}:{self.nt_hash}" if self.nt_hash else self.password
        )

        conn = Connection(
            server,
            user=ldap_username,
            password=ldap_password,
            authentication=NTLM,
            auto_referrals=False,
            receive_timeout=60,
            auto_range=True,
        )

        bound = False

        # Attempt Kerberos authentication if a TGT is available
        if self.tgt is not None and self.auth_method in ("kerberos", "auto"):
            logging.debug("Authenticating to LDAP server with Kerberos")
            try:
                conn = Connection(
                    server,
                    user=ldap_username,
                    password=ldap_password,
                    authentication=SASL,
                    sasl_mechanism=KERBEROS,
                    auto_referrals=False,
                )
                bound = self.ldap_kerberos(conn, hostname)
            except OSError as error:
                if "Name or service not known" in str(error):
                    logging.error(
                        f"DNS resolution error. Please, ensure than your system DNS is able to resolve {hostname}"
                    )
                    sys.exit(1)

            except Exception as exc:

                logging.debug(f"Kerberos authentication failed: {exc}")
                if self.auth_method == "auto":
                    logging.info("Kerberos auth failed, falling back to NTLM")
                    bound = False
                else:
                    logging.error("Kerberos authentication failed, no fallback enabled")

        # Fallback to NTLM if Kerberos did not succeed
        if not bound:
            conn = Connection(
                server,
                user=ldap_username,
                password=ldap_password,
                authentication=NTLM,
                auto_referrals=False,
            )
            logging.debug("Authenticating to LDAP server with NTLM")
            bound = conn.bind()

        # Handle unsuccessful binds
        if not bound:
            result = conn.result
            if (
                result["result"] == 49 and protocol == "ldap"
            ):  # LDAP result code for invalid credentials
                logging.warning(
                    "LDAP Authentication failed because LDAP signing is enabled. Trying LDAPS..."
                )
                return self.getLDAPConnection(hostname, ip_address, base_dn, "ldaps")
            else:
                error_message = result.get("message", "Unknown error during LDAP bind")
                logging.error(
                    f"Failure to authenticate with LDAP! Error: {error_message}"
                )
                raise CollectionException(
                    "Could not authenticate to LDAP. Check your credentials and LDAP server requirements."
                )

        return conn

    def ldap_kerberos(self, connection, hostname):
        # Hackery to authenticate with ldap3 using impacket Kerberos stack

        username = Principal(
            self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        servername = Principal(
            "ldap/%s" % hostname, type=constants.PrincipalNameType.NT_SRV_INST.value
        )

        tgs, cipher, _, sessionkey = getKerberosTGS(
            servername,
            self.domain,
            self.kdc,
            self.tgt["KDC_REP"],
            self.tgt["cipher"],
            self.tgt["sessionKey"],
        )

        # Let's build a NegTokenInit with a Kerberos AP_REQ
        blob = SPNEGO_NegTokenInit()

        # Kerberos
        blob["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]

        # Let's extract the ticket from the TGS
        tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs["ticket"])

        # Now let's build the AP_REQ
        apReq = AP_REQ()
        apReq["pvno"] = 5
        apReq["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = []
        apReq["ap-options"] = constants.encodeFlags(opts)
        seq_set(apReq, "ticket", ticket.to_asn1)

        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5
        authenticator["crealm"] = self.userdomain
        seq_set(authenticator, "cname", username.components_to_asn1)
        now = datetime.datetime.utcnow()

        authenticator["cusec"] = now.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 11
        # AP-REQ Authenticator (includes application authenticator
        # subkey), encrypted with the application session key
        # (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(
            sessionkey, 11, encodedAuthenticator, None
        )

        apReq["authenticator"] = noValue
        apReq["authenticator"]["etype"] = cipher.enctype
        apReq["authenticator"]["cipher"] = encryptedEncodedAuthenticator

        blob["MechToken"] = encoder.encode(apReq)

        # From here back to ldap3
        connection.open(read_server_info=False)
        request = bind_operation(
            connection.version,
            SASL,
            None,
            None,
            connection.sasl_mechanism,
            blob.getData(),
        )
        response = connection.post_send_single_response(
            connection.send("bindRequest", request, None)
        )[0]
        connection.result = response
        if response["result"] == 0:
            connection.bound = True
            connection.refresh_server_info()
        return response["result"] == 0

    def get_tgt(self):
        """
        Request a Kerberos TGT given our provided inputs.
        """
        username = Principal(
            self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        logging.info(f"Getting TGT for user {self.username}")

        try:
            tgt, cipher, _, session_key = getKerberosTGT(
                username,
                self.password,
                self.userdomain,
                unhexlify(self.lm_hash),
                unhexlify(self.nt_hash),
                self.aeskey,
                self.userdomain_kdc,
            )
        except Exception as exc:
            logging.debug(traceback.format_exc())
            if self.auth_method == "auto":
                logging.warning(
                    "Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: %s",
                    str(exc),
                )
                return
            else:
                # No other auth methods, so raise exception
                logging.error("Failed to get Kerberos TGT.")
                raise

        if self.userdomain != self.domain:
            # Try to get inter-realm TGT
            username = Principal(
                self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )
            servername = Principal(
                "krbtgt/%s" % self.domain,
                type=constants.PrincipalNameType.NT_SRV_INST.value,
            )
            # Get referral TGT
            tgs, cipher, _, sessionkey = getKerberosTGS(
                servername,
                self.userdomain,
                self.userdomain_kdc,
                tgt,
                cipher,
                session_key,
            )
            # See if this is a ticket for the correct domain
            refneeded = True
            while refneeded:
                decoded_tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                next_realm = str(decoded_tgs["ticket"]["sname"]["name-string"][1])
                if next_realm.upper() == self.domain.upper():
                    refneeded = False
                else:
                    # Get next referral TGT
                    logging.debug("Following referral across trust to get next TGT")
                    servername = Principal(
                        "krbtgt/%s" % self.domain,
                        type=constants.PrincipalNameType.NT_SRV_INST.value,
                    )
                    tgs, cipher, _, sessionkey = getKerberosTGS(
                        servername, next_realm, next_realm, tgs, cipher, sessionkey
                    )

            # Get foreign domain TGT
            servername = Principal(
                "krbtgt/%s" % self.domain,
                type=constants.PrincipalNameType.NT_SRV_INST.value,
            )
            tgs, cipher, _, sessionkey = getKerberosTGS(
                servername, self.domain, self.kdc, tgs, cipher, sessionkey
            )
            # Store this as our TGT
            self.tgt = {"KDC_REP": tgs, "cipher": cipher, "sessionKey": sessionkey}
        else:
            TGT = dict()
            TGT["KDC_REP"] = tgt
            TGT["cipher"] = cipher
            TGT["sessionKey"] = session_key
            self.tgt = TGT

    def get_tgs_for_smb(self, hostname):
        """
        Get a TGS for use with SMB Connection. We do this here to make sure the realms are correct,
        since impacket doesn't support cross-realm TGT usage and we don't want it to do its own Kerberos
        """
        username = Principal(
            self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        servername = Principal(
            "cifs/%s" % hostname, type=constants.PrincipalNameType.NT_SRV_INST.value
        )
        tgs, cipher, _, sessionkey = getKerberosTGS(
            servername,
            self.domain,
            self.kdc,
            self.tgt["KDC_REP"],
            self.tgt["cipher"],
            self.tgt["sessionKey"],
        )
        return {"KDC_REP": tgs, "cipher": cipher, "sessionKey": sessionkey}

    def load_ccache(self) -> bool:
        """
        Attempts to load a Kerberos Ticket-Granting Ticket (TGT) from a Kerberos credential cache (ccache) file.
        This method verifies if the TGT found in the cache matches the expected domain and username (if provided).

        Returns:
            bool: True if a valid TGT was loaded and matches the expected username and domain; False otherwise.

        Raises:
            FileNotFoundError: If the specified ccache file does not exist.
            Exception: General exception if ccache file loading fails or credential processing encounters an error.
        """
        krb5cc = os.getenv("KRB5CCNAME", f"/tmp/krb5cc_{os.getuid()}")

        if not os.path.isfile(krb5cc):
            logging.debug(
                f"No Kerberos credential cache file found at {krb5cc}, manually requesting TGT"
            )
            return False

        logging.debug(f"Using Kerberos credential cache: {krb5cc}")

        try:
            ccache = CCache.loadFile(krb5cc)
        except Exception as e:
            logging.error(f"Failed to load ccache file from {krb5cc}: {e}")
            return False

        principal_str = f"krbtgt/{self.domain.upper()}@{self.domain.upper()}"
        creds = ccache.getCredential(principal_str, anySPN=False)

        if creds is None:
            logging.debug("No valid credentials found in cache.")
            return False

        TGT = creds.toTGT()
        self.tgt = TGT
        logging.info("Using TGT from cache")

        decoded_tgt = decoder.decode(TGT["KDC_REP"], asn1Spec=AS_REP())[0]
        ticket_principal = Principal()
        ticket_principal.from_asn1(decoded_tgt, "crealm", "cname")
        formatted_principal = f"{ticket_principal}@{self.domain.upper()}"

        if not self.username:
            self.username = str(ticket_principal).split("@")[0]
            logging.info(f"Extracted the username from TGT: {self.username}")
        else:
            expected_principal = f"{self.username.lower()}@{self.domain.upper()}"
            if expected_principal.upper() != formatted_principal.upper():
                logging.warning(
                    f"Username in ccache file does not match supplied username! {formatted_principal} != {expected_principal}"
                )
                return False
            else:
                logging.info("Found TGT with correct principal in ccache file.")

        return True
