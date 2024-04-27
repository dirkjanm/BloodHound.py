def load_ccache(self):
    """
    Extract a TGT from a ccache file.
    """
    # If the kerberos credential cache is known, use that.
    krb5cc = os.getenv("KRB5CCNAME")

    # Otherwise, guess it.
    if krb5cc is None:
        try:
            krb5cc = "/tmp/krb5cc_%u" % os.getuid()
        except AttributeError:
            # This fails on Windows
            krb5cc = "nonexistingfile"

    if os.path.isfile(krb5cc):
        logging.debug("Using kerberos credential cache: %s", krb5cc)
    else:
        logging.debug(
            "No Kerberos credential cache file found, manually requesting TGT"
        )
        return False

    # Load TGT for our domain
    ccache = CCache.loadFile(krb5cc)
    principal = "krbtgt/%s@%s" % (self.domain.upper(), self.domain.upper())
    creds = ccache.getCredential(principal, anySPN=False)
    if creds is not None:
        TGT = creds.toTGT()
        # This we store for later
        self.tgt = TGT
        tgt, cipher, session_key = TGT["KDC_REP"], TGT["cipher"], TGT["sessionKey"]
        logging.info("Using TGT from cache")
    else:
        logging.debug("No valid credentials found in cache. ")
        return False

    # Verify if this ticket is actually for the specified user
    ticket = Ticket()
    decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    ticket.from_asn1(decoded_tgt["ticket"])

    tgt_principal = Principal()
    tgt_principal.from_asn1(decoded_tgt, "crealm", "cname")

    if not self.username:
        self.username = tgt_principal.split("@")[0]
    else:
        expected_principal = "%s@%s" % (self.username.lower(), self.domain.upper())
        if expected_principal.upper() != str(tgt_principal).upper():
            logging.warning(
                "Username in ccache file does not match supplied username! %s != %s",
                tgt_principal,
                expected_principal,
            )
            return False

    logging.info("Found TGT with correct principal in ccache file.")
    return True
