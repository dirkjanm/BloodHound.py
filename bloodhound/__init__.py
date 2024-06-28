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
import sys
import logging
from collections import deque


# Local library imports
from bloodhound import core, cli


"""
BloodHound.py is a Python port of BloodHound, designed to run on Linux and Windows.
"""

def main():
    args = cli.parse_arguments()

    cli.setup_logging(verbose=args.v)

    # Initialize variables for LM and NT hashes
    lm, nt = "", ""

    # Only attempt to split hashes if they are provided
    if args.hashes:
        try:
            lm, nt = args.hashes.split(":")
        except ValueError:
            logging.error(
                "Hashes provided in an incorrect format. Expected format: LM:NT"
            )
            sys.exit(1)

    # Queue to manage domains to be processed
    domains_to_process = deque([args.domain])
    handled_domains = set()

    while domains_to_process:
        current_domain = domains_to_process.popleft()
        if current_domain in handled_domains:
            continue

        # Perform the ingest on the current domain
        bloodhound = core.ingest(
            username=args.username,
            password=args.password,
            domain=current_domain,
            auth_method=args.auth_method,
            lm_hash=lm,
            nt_hash=nt,
            aes_key=args.aesKey,
            nameserver=args.nameserver,
            dns_tcp=args.dns_tcp,
            dns_timeout=args.dns_timeout,
            use_ldaps=args.use_ldaps,
            collection_method=args.collectionmethod,
            workers=args.workers,
            disable_pooling=args.disable_pooling,
            computerfile=args.computerfile,
            cachefile=args.cachefile,
            exclude_dcs=args.exclude_dcs,
            file_name_prefix=args.outputprefix,
            domain_controller=args.domain_controller,
            global_catalog=args.global_catalog,
            kerberos=args.kerberos,
            disable_autogc=args.disable_autogc
        )

        # Add the current domain to the handled set
        handled_domains.add(current_domain)

        if args.crawl:
            # Add newly discovered trusted domains to the queue if not already handled
            for trusted_domain in bloodhound.trusted_domains_names:
                if trusted_domain not in handled_domains:
                    domains_to_process.append(trusted_domain)

    # If args --zip is true, the compress output
    if args.zip:
        prefix = ""
        if args.outputprefix:
            prefix = f"{args.outputprefix}_"

        prefix += args.domain
        cli.zip_output(prefix=prefix)



if __name__ == "__main__":
    main()
