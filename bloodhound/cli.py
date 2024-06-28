# Built-in imports
import argparse
import logging
import sys
import datetime
import os
from zipfile import ZipFile


def zip_output(prefix: str = None, output_dir: str = '.', cleanup: bool = True) -> None:
    """
    Creates a zip archive of JSON files that match a specified prefix.

    This function zips all JSON files in the current working directory that start with the specified prefix or a generated timestamp prefix if no prefix is provided.
    After zipping, it can optionally delete the original files.

    Args:
        prefix (str, optional): Prefix to filter which files to zip. If None, uses a timestamp as the prefix.
        output_dir (str, optional): Directory where the zip file will be stored. Defaults to the current directory.
        cleanup (bool, optional): Whether to delete the original files after zipping. Defaults to True.

    Raises:
        FileNotFoundError: If the specified output directory does not exist.

    Returns:
        None: The function creates a zip file and optionally deletes the original files but returns nothing.
    """
    if not os.path.exists(output_dir):
        raise FileNotFoundError(f"The specified output directory {output_dir} does not exist.")

    # For adding timestamp prefix to the output files, formatted in ISO 8601 style
    timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    zip_file_name = f"{prefix}_{timestamp}_bloodhound_data.zip" if prefix else f"{timestamp}_bloodhound_data.zip"
    zip_file_path = os.path.join(output_dir, zip_file_name)

    with ZipFile(zip_file_path, 'w') as zip:
        # For each file that matches the criteria
        for each_file in os.listdir(os.getcwd()):
            if each_file.endswith("json"):
                file_path = os.path.join(os.getcwd(), each_file)
                zip.write(file_path, arcname=each_file)
                if cleanup:
                    os.remove(file_path)

    logging.info(f"Successfully created and filled {zip_file_path}")


def setup_logging(verbose: bool = False):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    stream = logging.StreamHandler(sys.stderr)
    stream.setLevel(logging.DEBUG)

    formatter = logging.Formatter("%(levelname)s: %(message)s")
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    if verbose is True:
        logger.setLevel(logging.DEBUG)

def parse_arguments():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="Python based ingestor for BloodHound\nFor help or reporting issues, visit https://github.com/dirkjanm/BloodHound.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-c",
        "--collectionmethod",
        action="store",
        default="Default",
        help="Which information to collect. Supported: Group, LocalAdmin, Session, "
        "Trusts, Default (all previous), DCOnly (no computer connections), DCOM, RDP,"
        "PSRemote, LoggedOn, Container, ObjectProps, ACL, All (all except LoggedOn). "
        "You can specify more than one by separating them with a comma. (default: Default)",
    )
    parser.add_argument(
        "-d", "--domain", action="store", default="", help="Domain to query."
    )
    parser.add_argument("-v", action="store_true", help="Enable verbose output")
    helptext = (
        "Specify one or more authentication options. \n"
        "By default Kerberos authentication is used and NTLM is used as fallback. \n"
        "Kerberos tickets are automatically requested if a password or hashes are specified."
    )
    auopts = parser.add_argument_group("authentication options", description=helptext)
    auopts.add_argument(
        "-u",
        "--username",
        action="store",
        help="Username. Format: username[@domain]; If the domain is unspecified, the current domain is used.",
    )
    auopts.add_argument("-p", "--password", action="store", help="Password")
    auopts.add_argument("-k", "--kerberos", action="store_true", help="Use kerberos")
    auopts.add_argument("--hashes", action="store", help="LM:NLTM hashes")
    auopts.add_argument(
        "-aesKey",
        action="store",
        metavar="hex key",
        help="AES key to use for Kerberos Authentication (128 or 256 bits)",
    )
    auopts.add_argument(
        "--auth-method",
        choices=("auto", "ntlm", "kerberos"),
        default="auto",
        action="store",
        help="Authentication methods. Force Kerberos or NTLM only or use auto for Kerberos with NTLM fallback",
    )
    coopts = parser.add_argument_group("collection options")
    coopts.add_argument(
        "-ns",
        "--nameserver",
        action="store",
        help="Alternative name server to use for queries",
    )
    coopts.add_argument(
        "--dns-tcp", action="store_true", help="Use TCP instead of UDP for DNS queries"
    )
    coopts.add_argument(
        "--dns-timeout",
        action="store",
        type=int,
        default=3,
        help="DNS query timeout in seconds (default: 3)",
    )
    coopts.add_argument(
        "-dc",
        "--domain-controller",
        metavar="HOST",
        action="store",
        help="Override which DC to query (hostname)",
    )
    coopts.add_argument(
        "-gc",
        "--global-catalog",
        metavar="HOST",
        action="store",
        help="Override which GC to query (hostname)",
    )
    coopts.add_argument(
        "-w",
        "--workers",
        action="store",
        type=int,
        default=10,
        help="Number of workers for computer enumeration (default: 10)",
    )
    coopts.add_argument(
        "--exclude-dcs",
        action="store_true",
        help="Skip DCs during computer enumeration",
    )
    coopts.add_argument(
        "--disable-pooling",
        action="store_true",
        help="Don't use subprocesses for ACL parsing (only for debugging purposes)",
    )
    coopts.add_argument(
        "--disable-autogc",
        action="store_true",
        help="Don't automatically select a Global Catalog (use only if it gives errors)",
    )

    coopts.add_argument(
        "--crawl",
        action="store_true",
        help="Enable crawling of discovered domains to dynamically ingest data from trusted domains."
    )

    coopts.add_argument(
        "--zip",
        action="store_true",
        help="Compress the JSON output files into a zip archive",
    )
    coopts.add_argument(
        "--computerfile",
        action="store",
        help="File containing computer FQDNs to use as allowlist for any computer based methods",
    )
    coopts.add_argument("--cachefile", action="store", help="Cache file (experimental)")
    coopts.add_argument(
        "--use-ldaps",
        action="store_true",
        help="Use LDAP over TLS on port 636 by default",
    )
    coopts.add_argument(
        "-op",
        "--outputprefix",
        metavar="PREFIX_NAME",
        action="store",
        help="String to prepend to output file names",
    )

    return parser.parse_args()