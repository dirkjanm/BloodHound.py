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

import logging
import queue
import threading
from bloodhound.ad.utils import ADUtils, AceResolver
from bloodhound.ad.computer import ADComputer
from bloodhound.enumeration.acls import AclEnumerator, parse_binary_acl
from bloodhound.enumeration.outputworker import OutputWorker

class MembershipEnumerator(object):
    """
    Class to enumerate memberships in the domain.
    Contains the dumping functions which
    methods from the bloodhound.ad module.
    """
    def __init__(self, addomain, addc, collect, disable_pooling):
        """
        Membership enumeration. Enumerates all groups/users/other memberships.
        """
        self.addomain = addomain
        self.addc = addc
        # Store collection methods specified
        self.collect = collect
        self.disable_pooling = disable_pooling
        self.aclenumerator = AclEnumerator(addomain, addc, collect)
        self.aceresolver = AceResolver(addomain, addomain.objectresolver)
        self.result_q = None

    def get_membership(self, member):
        """
        Attempt to resolve the membership (DN) of a group to an object
        """
        # First assume it is a user
        try:
            resolved_entry = self.addomain.users[member]
        except KeyError:
            # Try if it is a group
            try:
                resolved_entry = self.addomain.groups[member]
            except KeyError:
                # Try if it is a computer
                try:
                    entry = self.addomain.computers[member]
                    # Computers are stored as raw entries
                    resolved_entry = ADUtils.resolve_ad_entry(entry)
                except KeyError:
                    use_gc = ADUtils.ldap2domain(member) != self.addomain.domain
                    qobject = self.addomain.objectresolver.resolve_distinguishedname(member, use_gc=use_gc)
                    if qobject is None:
                        return None
                    resolved_entry = ADUtils.resolve_ad_entry(qobject)
                    # Store it in the cache
                    if resolved_entry['type'] == 'user':
                        self.addomain.users[member] = resolved_entry
                    if resolved_entry['type'] == 'group':
                        self.addomain.groups[member] = resolved_entry
                    # Computers are stored as raw entries
                    if resolved_entry['type'] == 'computer':
                        self.addomain.computers[member] = qobject
        return {
            "MemberId": resolved_entry['objectid'],
            "MemberType": resolved_entry['type'].capitalize()
        }

    @staticmethod
    def get_primary_membership(entry):
        """
        Construct primary membership from RID to SID (BloodHound 3.0 only)
        """
        try:
            primarygroupid = int(entry['attributes']['primaryGroupID'])
        except (TypeError, KeyError):
            # Doesn't have a primarygroupid, means it is probably a Group instead of a user
            return None
        return '%s-%d' % ('-'.join(entry['attributes']['objectSid'].split('-')[:-1]), primarygroupid)

    @staticmethod
    def add_user_properties(user, entry):
        """
        Resolve properties for user objects
        """
        props = user['Properties']
        # print entry
        # Is user enabled? Checked by seeing if the UAC flag 2 (ACCOUNT_DISABLED) is not set
        props['enabled'] = ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 2 == 0
        props['lastlogon'] = ADUtils.win_timestamp_to_string(
            ADUtils.get_entry_property(entry, 'lastLogon', default=0, raw=True)
        )
        if props['lastlogon'] == 0:
            props['lastlogon'] = -1
        props['lastlogontimestamp'] = ADUtils.win_timestamp_to_string(
            ADUtils.get_entry_property(entry, 'lastlogontimestamp', default=0, raw=True)
        )
        if props['lastlogontimestamp'] == 0:
            props['lastlogontimestamp'] = -1
        props['pwdlastset'] = ADUtils.win_timestamp_to_string(
            ADUtils.get_entry_property(entry, 'pwdLastSet', default=0, raw=True)
        )
        props['dontreqpreauth'] = ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00400000 == 0x00400000
        props['sensitive'] = ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00100000 == 0x00100000
        props['serviceprincipalnames'] = ADUtils.get_entry_property(entry, 'servicePrincipalName', [])
        props['hasspn'] = len(props['serviceprincipalnames']) > 0
        props['displayname'] = ADUtils.get_entry_property(entry, 'displayName')
        props['email'] = ADUtils.get_entry_property(entry, 'mail')
        props['title'] = ADUtils.get_entry_property(entry, 'title')
        props['homedirectory'] = ADUtils.get_entry_property(entry, 'homeDirectory')
        props['description'] = ADUtils.get_entry_property(entry, 'description')
        props['userpassword'] = ADUtils.get_entry_property(entry, 'userPassword')
        props['admincount'] = ADUtils.get_entry_property(entry, 'adminCount', 0) == 1
        if len(ADUtils.get_entry_property(entry, 'msDS-AllowedToDelegateTo', [])) > 0:
            props['allowedtodelegate'] = ADUtils.get_entry_property(entry, 'msDS-AllowedToDelegateTo', [])
        props['sidhistory'] = ADUtils.get_entry_property(entry, 'sIDHistory', [])

    def enumerate_users(self):
        filename = 'users.json'

        # Should we include extra properties in the query?
        with_properties = 'objectprops' in self.collect
        acl = 'acl' in self.collect
        entries = self.addc.get_users(include_properties=with_properties, acl=acl)

        logging.debug('Writing users to file: %s', filename)

        # Use a separate queue for processing the results
        self.result_q = queue.Queue()
        results_worker = threading.Thread(target=OutputWorker.membership_write_worker, args=(self.result_q, 'users', filename))
        results_worker.daemon = True
        results_worker.start()

        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()

        # This loops over a generator, results are fetched from LDAP on the go
        for entry in entries:
            resolved_entry = ADUtils.resolve_ad_entry(entry)
            # Skip trust objects
            if resolved_entry['type'] == 'trustaccount':
                continue
            user = {
                "AllowedToDelegate": [],
                "ObjectIdentifier": ADUtils.get_entry_property(entry, 'objectSid'),
                "PrimaryGroupSid": MembershipEnumerator.get_primary_membership(entry),
                "Properties": {
                    "name": resolved_entry['principal'],
                    "domain": self.addomain.domain.upper(),
                    "objectid": ADUtils.get_entry_property(entry, 'objectSid'),
                    "distinguishedname":ADUtils.get_entry_property(entry, 'distinguishedName'),
                    "highvalue": False,
                    "unconstraineddelegation": ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00080000 == 0x00080000,
                    "passwordnotreqd": ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00000020 == 0x00000020
                },
                "Aces": [],
                "SPNTargets": [],
                "HasSIDHistory": []
            }

            if with_properties:
                MembershipEnumerator.add_user_properties(user, entry)
                if 'allowedtodelegate' in user['Properties']:
                    for host in user['Properties']['allowedtodelegate']:
                        try:
                            target = host.split('/')[1]
                        except IndexError:
                            logging.warning('Invalid delegation target: %s', host)
                            continue
                        try:
                            sid = self.addomain.computersidcache.get(target.lower())
                            user['AllowedToDelegate'].append(sid)
                        except KeyError:
                            if '.' in target:
                                user['AllowedToDelegate'].append(target.upper())
                # Parse SID history
                if len(user['Properties']['sidhistory']) > 0:
                    for historysid in user['Properties']['sidhistory']:
                        user['HasSIDHistory'].append(self.aceresolver.resolve_binary_sid(historysid))

            # If this is a GMSA, process it's ACL. We don't bother with threads/processes here
            # since these accounts shouldn't be that common and neither should they have very complex
            # DACLs which control who can read their password
            if ADUtils.get_entry_property(entry, 'msDS-GroupMSAMembership', default=b'', raw=True) != b'':
                self.parse_gmsa(user, entry)

            self.addomain.users[entry['dn']] = resolved_entry
            # If we are enumerating ACLs, we break out of the loop here
            # this is because parsing ACLs is computationally heavy and therefor is done in subprocesses
            if acl:
                if self.disable_pooling:
                    # Debug mode, don't run this pooled since it hides exceptions
                    self.process_acldata(parse_binary_acl(user, 'user', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map))
                else:
                    # Process ACLs in separate processes, then call the processing function to resolve entries and write them to file
                    self.aclenumerator.pool.apply_async(parse_binary_acl, args=(user, 'user', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map), callback=self.process_acldata)
            else:
                # Write it to the queue -> write to file in separate thread
                # this is solely for consistency with acl parsing, the performance improvement is probably minimal
                self.result_q.put(user)

        # If we are parsing ACLs, close the parsing pool first
        # then close the result queue and join it
        if acl and not self.disable_pooling:
            self.aclenumerator.pool.close()
            self.aclenumerator.pool.join()
            self.result_q.put(None)
        else:
            self.result_q.put(None)
        self.result_q.join()

        logging.debug('Finished writing users')

    def enumerate_groups(self):

        highvalue = ["S-1-5-32-544", "S-1-5-32-550", "S-1-5-32-549", "S-1-5-32-551", "S-1-5-32-548"]

        def is_highvalue(sid):
            if sid.endswith("-512") or sid.endswith("-516") or sid.endswith("-519") or sid.endswith("-520"):
                return True
            if sid in highvalue:
                return True
            return False

        # Should we include extra properties in the query?
        with_properties = 'objectprops' in self.collect
        acl = 'acl' in self.collect

        filename = 'groups.json'
        entries = self.addc.get_groups(include_properties=with_properties, acl=acl)

        logging.debug('Writing groups to file: %s', filename)

        # Use a separate queue for processing the results
        self.result_q = queue.Queue()
        results_worker = threading.Thread(target=OutputWorker.membership_write_worker, args=(self.result_q, 'groups', filename))
        results_worker.daemon = True
        results_worker.start()

        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()

        for entry in entries:
            resolved_entry = ADUtils.resolve_ad_entry(entry)
            self.addomain.groups[entry['dn']] = resolved_entry
            try:
                sid = entry['attributes']['objectSid']
            except KeyError:
                #Somehow we found a group without a sid?
                logging.warning('Could not determine SID for group %s', entry['attributes']['distinguishedName'])
                continue
            group = {
                "ObjectIdentifier": sid,
                "Properties": {
                    "domain": self.addomain.domain.upper(),
                    "objectid": sid,
                    "highvalue": is_highvalue(sid),
                    "name": resolved_entry['principal'],
                    "distinguishedname": ADUtils.get_entry_property(entry, 'distinguishedName')
                },
                "Members": [],
                "Aces": []
            }
            if sid in ADUtils.WELLKNOWN_SIDS:
                # Prefix it with the domain
                group['ObjectIdentifier'] = '%s-%s' % (self.addomain.domain.upper(), sid)
                group['Properties']['objectid'] = group['ObjectIdentifier']
            if with_properties:
                group['Properties']['admincount'] = ADUtils.get_entry_property(entry, 'adminCount', default=0) == 1
                group['Properties']['description'] = ADUtils.get_entry_property(entry, 'description')

            for member in entry['attributes']['member']:
                resolved_member = self.get_membership(member)
                if resolved_member:
                    group['Members'].append(resolved_member)

            # If we are enumerating ACLs, we break out of the loop here
            # this is because parsing ACLs is computationally heavy and therefor is done in subprocesses
            if acl:
                if self.disable_pooling:
                    # Debug mode, don't run this pooled since it hides exceptions
                    self.process_acldata(parse_binary_acl(group, 'group', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map))
                else:
                    # Process ACLs in separate processes, then call the processing function to resolve entries and write them to file
                    self.aclenumerator.pool.apply_async(parse_binary_acl, args=(group, 'group', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map), callback=self.process_acldata)
            else:
                # Write it to the queue -> write to file in separate thread
                # this is solely for consistency with acl parsing, the performance improvement is probably minimal
                self.result_q.put(group)

        self.write_default_groups()

        # If we are parsing ACLs, close the parsing pool first
        # then close the result queue and join it
        if acl and not self.disable_pooling:
            self.aclenumerator.pool.close()
            self.aclenumerator.pool.join()
            self.result_q.put(None)
        else:
            self.result_q.put(None)
        self.result_q.join()

        logging.debug('Finished writing groups')

    def enumerate_computers_dconly(self):
        '''
        Enumerate computer objects. This function is only used if no
        collection was requested that required connecting to computers anyway.
        '''
        filename = 'computers.json'

        acl = 'acl' in self.collect
        entries = self.addc.ad.computers

        logging.debug('Writing computers ACL to file: %s', filename)

        # Use a separate queue for processing the results
        self.result_q = queue.Queue()
        results_worker = threading.Thread(target=OutputWorker.membership_write_worker, args=(self.result_q, 'computers', filename))
        results_worker.daemon = True
        results_worker.start()

        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()

        # This loops over the cached entries
        for entry in entries:
            if not 'attributes' in entry:
                continue

            if 'dNSHostName' not in entry['attributes']:
                continue

            hostname = entry['attributes']['dNSHostName']
            if not hostname:
                continue
            samname = entry['attributes']['sAMAccountName']

            cobject = ADComputer(hostname=hostname, samname=samname, ad=self.addomain, addc=self.addc, objectsid=entry['attributes']['objectSid'])
            cobject.primarygroup = MembershipEnumerator.get_primary_membership(entry)
            computer = cobject.get_bloodhound_data(entry, self.collect, skip_acl=True)

            # If we are enumerating ACLs, we break out of the loop here
            # this is because parsing ACLs is computationally heavy and therefor is done in subprocesses
            if acl:
                if self.disable_pooling:
                    # Debug mode, don't run this pooled since it hides exceptions
                    self.process_acldata(parse_binary_acl(computer, 'computer', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map))
                else:
                    # Process ACLs in separate processes, then call the processing function to resolve entries and write them to file
                    self.aclenumerator.pool.apply_async(parse_binary_acl, args=(computer, 'computer', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map), callback=self.process_acldata)
            else:
                # Write it to the queue -> write to file in separate thread
                # this is solely for consistency with acl parsing, the performance improvement is probably minimal
                self.result_q.put(computer)

        # If we are parsing ACLs, close the parsing pool first
        # then close the result queue and join it
        if acl and not self.disable_pooling:
            self.aclenumerator.pool.close()
            self.aclenumerator.pool.join()
            self.result_q.put(None)
        else:
            self.result_q.put(None)
        self.result_q.join()

        logging.debug('Finished writing computers')

    def parse_gmsa(self, user, entry):
        """
        Parse GMSA DACL which states which users can read the password
        """
        _, aces = parse_binary_acl(user, 'user', ADUtils.get_entry_property(entry, 'msDS-GroupMSAMembership', raw=True), self.addc.objecttype_guid_map)
        processed_aces = self.aceresolver.resolve_aces(aces)
        for ace in processed_aces:
            if ace['RightName'] == 'Owner':
                continue
            ace['RightName'] = 'ReadGMSAPassword'
            user['Aces'].append(ace)

    def process_acldata(self, result):
        """
        Process ACLs that resulted from parsing with cstruct
        """
        data, aces = result
        # Parse aces
        data['Aces'] += self.aceresolver.resolve_aces(aces)
        self.result_q.put(data)

    def write_default_groups(self):
        """
        Put default groups in the groups.json file
        """

        # Domain controllers
        rootdomain = self.addc.get_root_domain().upper()
        entries = self.addc.get_domain_controllers()

        group = {
            "ObjectIdentifier": "%s-S-1-5-9" % rootdomain,
            "Properties": {
                "domain": rootdomain.upper(),
                "name": "ENTERPRISE DOMAIN CONTROLLERS@%s" % rootdomain,
            },
            "Members": [],
            "Aces": []
        }
        for entry in entries:
            resolved_entry = ADUtils.resolve_ad_entry(entry)
            memberdata = {
                "MemberId": resolved_entry['objectid'],
                "MemberType": resolved_entry['type'].capitalize()
            }
            group["Members"].append(memberdata)
        self.result_q.put(group)

        domainsid = self.addomain.domain_object.sid
        domainname = self.addomain.domain.upper()

        # Everyone
        evgroup = {
            "ObjectIdentifier": "%s-S-1-1-0" % domainname,
            "Properties": {
                "domain": domainname,
                "name": "EVERYONE@%s" % domainname,
            },
            "Members": [
                {
                    "MemberId": "%s-515" % domainsid,
                    "MemberType": "Group"
                },
                {
                    "MemberId": "%s-513" % domainsid,
                    "MemberType": "Group"
                }
            ],
            "Aces": []
        }
        self.result_q.put(evgroup)

        # Authenticated users
        augroup = {
            "ObjectIdentifier": "%s-S-1-5-11" % domainname,
            "Properties": {
                "domain": domainname,
                "name": "AUTHENTICATED USERS@%s" % domainname,
            },
            "Members": [
                {
                    "MemberId": "%s-515" % domainsid,
                    "MemberType": "Group"
                },
                {
                    "MemberId": "%s-513" % domainsid,
                    "MemberType": "Group"
                }
            ],
            "Aces": []
        }
        self.result_q.put(augroup)


    def enumerate_memberships(self):
        """
        Run appropriate enumeration tasks
        """
        self.enumerate_users()
        self.enumerate_groups()
        if not ('localadmin' in self.collect
                or 'session' in self.collect
                or 'loggedon' in self.collect
                or 'experimental' in self.collect):
            self.enumerate_computers_dconly()
