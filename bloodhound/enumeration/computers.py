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
import Queue
import threading
import logging
import traceback
from impacket.dcerpc.v5.rpcrt import DCERPCException
from bloodhound.enumeration.outputworker import OutputWorker
from bloodhound.ad.computer import ADComputer
from bloodhound.ad.utils import ADUtils

class ComputerEnumerator(object):
    """
    Class to enumerate computers in the domain.
    Contains the threading logic and workers which will call the collection
    methods from the bloodhound.ad module.
    """
    def __init__(self, addomain, do_gc_lookup=True):
        """
        Computer enumeration. Enumerates all computers in the given domain.
        Every domain enumerated will get its own instance of this class.
        """
        self.addomain = addomain
        # Blacklist and whitelist are only used for debugging purposes
        self.blacklist = []
        self.whitelist = []
        self.do_gc_lookup = do_gc_lookup


    def enumerate_computers(self, computers, num_workers=10):
        """
            Enumerates the computers in the domain. Is threaded, you can specify the number of workers.
            Will spawn threads to resolve computers and enumerate the information.
        """
        q = Queue.Queue()

        result_q = Queue.Queue()
        results_worker = threading.Thread(target=OutputWorker.write_worker, args=(result_q, 'admins.csv', 'sessions.csv'))
        results_worker.daemon = True
        results_worker.start()
        logging.info('Starting computer enumeration with %d workers', num_workers)
        if len(computers) / num_workers > 500:
            logging.info('The workload seems to be rather large. Consider increasing the number of workers.')
        for _ in range(0, num_workers):
            t = threading.Thread(target=self.work, args=(q,result_q))
            t.daemon = True
            t.start()

        for _, computer in computers.iteritems():
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

            q.put((hostname, samname))
        q.join()
        result_q.put(None)
        result_q.join()

    def process_computer(self, hostname, samname, results_q):
        """
            Processes a single computer, pushes the results of the computer to the given Queue.
        """
        logging.debug('Querying computer: %s', hostname)
        c = ADComputer(hostname=hostname, samname=samname, ad=self.addomain)
        if c.try_connect() == True:
            # Maybe try connection reuse?
            try:
                sessions = c.rpc_get_sessions()
                c.rpc_get_local_admins()
                c.rpc_resolve_sids()
                c.rpc_close()
                # c.rpc_get_domain_trusts()

                for admin in c.admins:
                    # Put the result on the results queue.
                    results_q.put(('admin', u'%s,%s@%s,%s\n' %
                                   (unicode(admin['computer']).upper(),
                                    unicode(admin['name']).upper(),
                                    admin['domain'].upper(),
                                    unicode(admin['use']).lower())))

                if sessions is None:
                    sessions = []

                for ses in sessions:
                    # For every session, resolve the SAM name in the GC if needed
                    domain = self.addomain.domain
                    if self.addomain.num_domains > 1 and self.do_gc_lookup:
                        try:
                            users = self.addomain.samcache.get(samname)
                        except KeyError:
                            # Look up the SAM name in the GC
                            users = self.addomain.objectresolver.gc_sam_lookup(ses['user'])
                            if users is None:
                                # Unknown user
                                continue
                            self.addomain.samcache.put(samname, users)
                    else:
                        users = [((u'%s@%s' % (ses['user'], domain)).upper(), 2)]

                    # Resolve the IP to obtain the host the session is from
                    try:
                        target = self.addomain.dnscache.get(ses['source'])
                    except KeyError:
                        target = ADUtils.ip2host(ses['source'], self.addomain.dnsresolver)
                        # Even if the result is the IP (aka could not resolve PTR) we still cache
                        # it since this result is unlikely to change during this run
                        self.addomain.dnscache.put_single(ses['source'], target)
                    if ':' in target:
                        # IPv6 address, not very useful
                        continue
                    if '.' not in target:
                        logging.debug('Resolved target does not look like an IP or domain. Assuming hostname: %s', target)
                        target = '%s.%s' % (target, domain)
                    # Put the result on the results queue.
                    for user in users:
                        results_q.put(('session', u'%s,%s,%u\n' % (user[0], target, user[1])))

            except DCERPCException:
                logging.warning('Querying sessions failed: %s' % hostname)
            except Exception as e:
                logging.error('Unhandled exception in computer processing: %s', str(e))
                logging.info(traceback.format_exc())


    def work(self, q, results_q):
        """
            Work function, will obtain work from the given queue and will push results on the results_q.
        """
        logging.debug('Start working')

        while True:
            hostname, samname = q.get()
            logging.info('Querying computer: %s', hostname)
            self.process_computer(hostname, samname, results_q)
            q.task_done()
