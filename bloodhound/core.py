# Built-in imports
import logging
import sys
import time
import datetime
import re

# Local library imports
from bloodhound.ad.domain import AD
from bloodhound.ad.authentication import ADAuthentication
from bloodhound.ad.domain import ADDC
from bloodhound.enumeration.computers import ComputerEnumerator
from bloodhound.enumeration.memberships import MembershipEnumerator
from bloodhound.enumeration.domains import DomainEnumerator

def ingest(username, password, domain, auth_method, lm_hash, nt_hash, aes_key, nameserver,
           dns_tcp, dns_timeout, use_ldaps, collection_method, workers, disable_pooling,
           computerfile, cachefile, exclude_dcs, file_name_prefix, domain_controller, global_catalog, kerberos, disable_autogc):
    """
    Performs the data collection and processing for BloodHound.
    """

    logging.info(f"Starting data ingestion for domain: {domain}")

    auth = ADAuthentication(
        username=username,
        password=password,
        domain=domain,
        auth_method=auth_method,
        lm_hash=lm_hash,
        nt_hash=nt_hash,
        aeskey=aes_key,
    )

    ad = AD(
        auth=auth,
        domain=domain,
        nameserver=nameserver,
        dns_tcp=dns_tcp,
        dns_timeout=dns_timeout,
        use_ldaps=use_ldaps,
    )

    # Resolve collection methods
    collect = resolve_collection_methods(collection_method)
    if not collect:
        return
    logging.debug("Resolved collection methods: %s", ", ".join(list(collect)))

    logging.debug("Using DNS to retrieve domain information")
    ad.dns_resolve(
        domain=domain,
        global_catalog=True if global_catalog else False,
        disable_autogc=disable_autogc
    )

    # Override the detected DC / GC if specified
    if domain_controller:
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain_controller):
            logging.error(
                "The specified domain controller %s looks like an IP address, but requires a hostname (FQDN).\n"
                "Use the -ns flag to specify a DNS server IP if the hostname does not resolve on your default nameserver.",
                domain_controller,
            )
            sys.exit(1)
        ad.override_dc(domain_controller)
        logging.debug("Using supplied domain controller as KDC")
        auth.set_kdc(domain_controller)

    if global_catalog:
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", global_catalog):
            logging.error(
                "The specified global catalog server %s looks like an IP address, but requires a hostname (FQDN).\n"
                "Use the -ns flag to specify a DNS server IP if the hostname does not resolve on your default nameserver.",
                global_catalog,
            )
            sys.exit(1)
        ad.override_gc(global_catalog)

    if auth_method in ("auto", "kerberos"):
        if kerberos is True:
            logging.debug("Authentication: Kerberos ccache")
            # kerberize()
            if not auth.load_ccache():
                logging.debug(
                    "Could not load ticket from ccache, trying to request a TGT instead"
                )
                auth.get_tgt()
        else:
            auth.get_tgt()


    bloodhound = BloodHound(ad)
    bloodhound.connect()
    bloodhound.run(
        collect=collect,
        num_workers=workers,
        disable_pooling=disable_pooling,
        computerfile=computerfile,
        cachefile=cachefile,
        exclude_dcs=exclude_dcs,
        fileNamePrefix=file_name_prefix,
    )

    logging.info(f"End of data ingestion for domain: {domain}")

    return bloodhound

def resolve_collection_methods(methods):
    """
    Convert methods (string) to list of validated methods to resolve
    """
    valid_methods = [
        "group",
        "localadmin",
        "session",
        "trusts",
        "default",
        "all",
        "loggedon",
        "objectprops",
        "experimental",
        "acl",
        "dcom",
        "rdp",
        "psremote",
        "dconly",
        "container",
    ]
    default_methods = ["group", "localadmin", "session", "trusts"]
    # Similar to SharpHound, All is not really all, it excludes loggedon
    all_methods = [
        "group",
        "localadmin",
        "session",
        "trusts",
        "objectprops",
        "acl",
        "dcom",
        "rdp",
        "psremote",
        "container",
    ]
    # DC only, does not collect to computers
    dconly_methods = ["group", "trusts", "objectprops", "acl", "container"]
    if "," in methods:
        method_list = [method.lower() for method in methods.split(",")]
        validated_methods = []
        for method in method_list:
            if method not in valid_methods:
                logging.error("Invalid collection method specified: %s", method)
                return False

            if method == "default":
                validated_methods += default_methods
            elif method == "all":
                validated_methods += all_methods
            elif method == "dconly":
                validated_methods += dconly_methods
            else:
                validated_methods.append(method)
        return set(validated_methods)
    else:
        validated_methods = []
        # It is only one
        method = methods.lower()
        if method in valid_methods:
            if method == "default":
                validated_methods += default_methods
            elif method == "all":
                validated_methods += all_methods
            elif method == "dconly":
                validated_methods += dconly_methods
            else:
                validated_methods.append(method)
            return set(validated_methods)
        else:
            logging.error("Invalid collection method specified: %s", method)
            return False


class BloodHound(object):
    def __init__(self, ad):
        self.ad = ad
        self.ldap = None
        self.pdc = None
        self.sessions = []
        self.trusted_domains_names = []

    def connect(self):
        if len(self.ad.dcs()) == 0:
            logging.error(
                "Could not find a domain controller. Consider specifying a domain and/or DNS server."
            )
            sys.exit(1)

        if not self.ad.baseDN:
            logging.error(
                "Could not figure out the domain to query. Please specify this manually with -d"
            )
            sys.exit(1)

        pdc = self.ad.dcs()[0]
        logging.debug("Using LDAP server: %s", pdc)
        logging.debug("Using base DN: %s", self.ad.baseDN)

        if len(self.ad.kdcs()) > 0:
            kdc = self.ad.auth.kdc
            logging.debug("Using kerberos KDC: %s", kdc)
            logging.debug("Using kerberos realm: %s", self.ad.realm())

        # Create a domain controller object
        self.pdc = ADDC(pdc, self.ad)
        # Create an object resolver
        self.ad.create_objectresolver(self.pdc)

    def run(
        self,
        collect,
        num_workers=10,
        disable_pooling=False,
        computerfile="",
        cachefile=None,
        exclude_dcs=False,
        fileNamePrefix="",
    ):
        start_time = time.time()

        timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S") + f'_{self.ad.domain}_'

        if cachefile:
            self.ad.load_cachefile(cachefile)

        # Check early if we should enumerate computers as well
        do_computer_enum = any(
            method in collect
            for method in [
                "localadmin",
                "session",
                "loggedon",
                "experimental",
                "rdp",
                "dcom",
                "psremote",
            ]
        )

        if "group" in collect or "objectprops" in collect or "acl" in collect:
            # Fetch domains for later, computers if needed
            self.pdc.prefetch_info(
                "objectprops" in collect,
                "acl" in collect,
                cache_computers=do_computer_enum,
            )
            # Initialize enumerator
            membership_enum = MembershipEnumerator(
                self.ad, self.pdc, collect, disable_pooling
            )
            membership_enum.enumerate_memberships(
                timestamp=timestamp, fileNamePrefix=fileNamePrefix
            )
        elif "container" in collect:
            # Fetch domains for later, computers if needed
            self.pdc.prefetch_info(
                "objectprops" in collect,
                "acl" in collect,
                cache_computers=do_computer_enum,
            )
            # Initialize enumerator
            membership_enum = MembershipEnumerator(
                self.ad, self.pdc, collect, disable_pooling
            )
            membership_enum.do_container_collection(timestamp=timestamp)
        elif do_computer_enum:
            # We need to know which computers to query regardless
            # We also need the domains to have a mapping from NETBIOS -> FQDN for local admins
            self.pdc.prefetch_info(
                "objectprops" in collect, "acl" in collect, cache_computers=True
            )
        elif "trusts" in collect:
            # Prefetch domains
            self.pdc.get_domains("acl" in collect)

        if "trusts" in collect or "acl" in collect or "objectprops" in collect:
            trusts_enum = DomainEnumerator(self.ad, self.pdc)
            trusts_enum.dump_domain(
                collect, timestamp=timestamp, fileNamePrefix=fileNamePrefix
            )

            self.trusted_domains_names = trusts_enum.trusted_domains_names

        if do_computer_enum:
            # If we don't have a GC server, don't use it for deconflictation
            have_gc = len(self.ad.gcs()) > 0
            computer_enum = ComputerEnumerator(
                self.ad,
                self.pdc,
                collect,
                do_gc_lookup=have_gc,
                computerfile=computerfile,
                exclude_dcs=exclude_dcs,
            )
            computer_enum.enumerate_computers(
                self.ad.computers,
                num_workers=num_workers,
                timestamp=timestamp,
                fileNamePrefix=fileNamePrefix,
            )


        end_time = time.time()
        minutes, seconds = divmod(int(end_time - start_time), 60)
        logging.info("Done in %02dM %02dS" % (minutes, seconds))

