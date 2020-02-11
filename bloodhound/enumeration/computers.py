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
from __future__ import unicode_literals
import queue
import threading
import logging
import traceback
from impacket.dcerpc.v5.rpcrt import DCERPCException
from bloodhound.enumeration.outputworker import OutputWorker
from bloodhound.enumeration.memberships import MembershipEnumerator
from bloodhound.ad.computer import ADComputer
from bloodhound.ad.utils import ADUtils
from future.utils import itervalues, iteritems, native_str

class ComputerEnumerator(MembershipEnumerator):
    """
    Class to enumerate computers in the domain.
    Contains the threading logic and workers which will call the collection
    methods from the bloodhound.ad module.

    This class extends the MembershipEnumerator class just to inherit the
    membership lookup functions which are also needed for computers.
    """
    def __init__(self, addomain, addc, collect, do_gc_lookup=True):
        """
        Computer enumeration. Enumerates all computers in the given domain.
        Every domain enumerated will get its own instance of this class.
        """
        self.addomain = addomain
        self.addc = addc
        # Blacklist and whitelist are only used for debugging purposes
        self.blacklist = []
        self.whitelist = []
        self.do_gc_lookup = do_gc_lookup
        # Store collection methods specified
        self.collect = collect

    def enumerate_computers(self, computers, num_workers=10):
        """
            Enumerates the computers in the domain. Is threaded, you can specify the number of workers.
            Will spawn threads to resolve computers and enumerate the information.
        """
        process_queue = queue.Queue()

        result_q = queue.Queue()
        results_worker = threading.Thread(target=OutputWorker.write_worker, args=(result_q, 'computers.json'))
        results_worker.daemon = True
        results_worker.start()
        logging.info('Starting computer enumeration with %d workers', num_workers)
        if len(computers) / num_workers > 500:
            logging.info('The workload seems to be rather large. Consider increasing the number of workers.')
        for _ in range(0, num_workers):
            thread = threading.Thread(target=self.work, args=(process_queue, result_q))
            thread.daemon = True
            thread.start()

        for _, computer in iteritems(computers):
            if not 'attributes' in computer:
                continue

            if 'dNSHostName' not in computer['attributes']:
                continue

            hostname = computer['attributes']['dNSHostName']
            if not hostname:
                continue
            samname = computer['attributes']['sAMAccountName']
            # For debugging purposes only
            if hostname in self.blacklist:
                logging.info('Skipping computer: %s (blacklisted)', hostname)
                continue
            if len(self.whitelist) > 0 and hostname not in self.whitelist:
                logging.info('Skipping computer: %s (not whitelisted)', hostname)
                continue

            process_queue.put((hostname, samname, computer))
        process_queue.join()
        result_q.put(None)
        result_q.join()

    def process_computer(self, hostname, samname, objectsid, entry, results_q):
        """
            Processes a single computer, pushes the results of the computer to the given queue.
        """
        logging.debug('Querying computer: %s', hostname)
        c = ADComputer(hostname=hostname, samname=samname, ad=self.addomain, addc=self.addc, objectsid=objectsid)
        c.primarygroup = self.get_primary_membership(entry)
        if c.try_connect() == True:
            try:

                if 'session' in self.collect:
                    sessions = c.rpc_get_sessions()
                else:
                    sessions = []
                if 'localadmin' in self.collect:
                    unresolved = c.rpc_get_group_members(544, c.admins)
                    c.rpc_resolve_sids(unresolved, c.admins)
                if 'rdp' in self.collect:
                    unresolved = c.rpc_get_group_members(555, c.rdp)
                    c.rpc_resolve_sids(unresolved, c.rdp)
                if 'dcom' in self.collect:
                    unresolved = c.rpc_get_group_members(562, c.dcom)
                    c.rpc_resolve_sids(unresolved, c.dcom)
                if 'psremote' in self.collect:
                    unresolved = c.rpc_get_group_members(580, c.psremote)
                    c.rpc_resolve_sids(unresolved, c.psremote)
                if 'loggedon' in self.collect:
                    loggedon = c.rpc_get_loggedon()
                else:
                    loggedon = []
                if 'experimental' in self.collect:
                    services = c.rpc_get_services()
                    tasks = c.rpc_get_schtasks()
                else:
                    services = []
                    tasks = []

                c.rpc_close()
                # c.rpc_get_domain_trusts()

                if sessions is None:
                    sessions = []

                # Should we use the GC?
                use_gc = self.addomain.num_domains > 1 and self.do_gc_lookup

                # Process found sessions
                for ses in sessions:
                    # For every session, resolve the SAM name in the GC if needed
                    domain = self.addomain.domain
                    try:
                        users = self.addomain.samcache.get(samname)
                    except KeyError:
                        # Look up the SAM name in the GC
                        entries = self.addomain.objectresolver.resolve_samname(ses['user'], use_gc=use_gc)
                        if entries is not None:
                            users = [user['attributes']['objectSid'] for user in entries]
                        if entries is None or users == []:
                            logging.warning('Failed to resolve SAM name %s in current forest', samname)
                            continue
                        self.addomain.samcache.put(samname, users)

                    # Resolve the IP to obtain the host the session is from
                    try:
                        target = self.addomain.dnscache.get(ses['source'])
                    except KeyError:
                        # TODO: also use discovery based on port 445 connections similar to sharphound
                        target = ADUtils.ip2host(ses['source'], self.addomain.dnsresolver, self.addomain.dns_tcp)
                        # Even if the result is the IP (aka could not resolve PTR) we still cache
                        # it since this result is unlikely to change during this run
                        self.addomain.dnscache.put_single(ses['source'], target)
                    if ':' in target:
                        # IPv6 address, not very useful
                        continue
                    if '.' not in target:
                        logging.debug('Resolved target does not look like an IP or domain. Assuming hostname: %s', target)
                        target = '%s.%s' % (target, domain)
                    # Resolve target hostname
                    try:
                        hostsid = self.addomain.computersidcache.get(target.lower())
                    except KeyError:
                        logging.warning('Could not resolve hostname to SID: %s', target)
                        continue

                    # Put the result on the results queue.
                    for user in users:
                        c.sessions.append({'ComputerId':hostsid, 'UserId':user})
                if loggedon is None:
                    loggedon = []

                # Put the logged on users on the queue too
                for user, userdomain in loggedon:
                    # Construct fake UPN to cache this user
                    fupn = '%s@%s' % (user.upper(), userdomain.upper())
                    try:
                        users = self.addomain.samcache.get(fupn)
                    except KeyError:
                        entries = self.addomain.objectresolver.resolve_samname(user, use_gc=use_gc)
                        if entries is not None:
                            if len(entries) > 1:
                                for resolved_user in entries:
                                    edn = ADUtils.get_entry_property(resolved_user, 'distinguishedName')
                                    edom = ADUtils.ldap2domain(edn).lower()
                                    if edom == userdomain.lower():
                                        users = [resolved_user['attributes']['objectSid']]
                                        break
                                    logging.debug('Skipping resolved user %s since domain does not match (%s != %s)', edn, edom, userdomain.lower())
                            else:
                                users = [resolved_user['attributes']['objectSid'] for resolved_user in entries]
                        if entries is None or users == []:
                            logging.warning('Failed to resolve SAM name %s in current forest', samname)
                            continue
                        self.addomain.samcache.put(fupn, users)
                    for resultuser in users:
                        c.sessions.append({'ComputerId':objectsid, 'UserId':resultuser})

                # Process Tasks
                for taskuser in tasks:
                    c.sessions.append({'ComputerId':objectsid, 'UserId':taskuser})

                # Process Services
                for serviceuser in services:
                    try:
                        user = self.addomain.sidcache.get(serviceuser)
                    except KeyError:
                        # Resolve UPN in GC
                        userentry = self.addomain.objectresolver.resolve_upn(serviceuser)
                        # Resolve it to an entry and store in the cache
                        self.addomain.sidcache.put(serviceuser, userentry['attributes']['objectSid'])
                        user = userentry['attributes']['objectSid']
                    logging.debug('Resolved Service UPN to SID: %s', user['objectsid'])
                    c.sessions.append({'ComputerId':objectsid, 'UserId':user})

                results_q.put(('computer', c.get_bloodhound_data(entry, self.collect)))


            except DCERPCException:
                logging.debug(traceback.format_exc())
                logging.warning('Querying computer failed: %s', hostname)
            except Exception as e:
                logging.error('Unhandled exception in computer %s processing: %s', hostname, str(e))
                logging.info(traceback.format_exc())
        else:
            # Write the info we have to the file regardless
            try:
                results_q.put(('computer', c.get_bloodhound_data(entry, self.collect)))
            except Exception as e:
                logging.error('Unhandled exception in computer %s processing: %s', hostname, str(e))
                logging.info(traceback.format_exc())

    def work(self, process_queue, results_q):
        """
            Work function, will obtain work from the given queue and will push results on the results_q.
        """
        logging.debug('Start working')

        while True:
            hostname, samname, entry = process_queue.get()
            objectsid = entry['attributes']['objectSid']
            logging.info('Querying computer: %s', hostname)
            self.process_computer(hostname, samname, objectsid, entry, results_q)
            process_queue.task_done()
