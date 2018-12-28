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
import traceback
import codecs
import json
from ldap3.core.exceptions import LDAPKeyError
from bloodhound.ad.utils import ADUtils


class MembershipEnumerator(object):
    """
    Class to enumerate memberships in the domain.
    Contains the dumping functions which
    methods from the bloodhound.ad module.
    """
    def __init__(self, addomain, addc, collect):
        """
        Membership enumeration. Enumerates all groups/users/other memberships.
        """
        self.addomain = addomain
        self.addc = addc
        # Store collection methods specified
        self.collect = collect

    def get_membership(self, member):
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
                        return
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
            "MemberName": resolved_entry['principal'],
            "MemberType": resolved_entry['type'].capitalize()
        }

    def get_primary_membership(self, entry):
        """
        Looks up the primary membership based on RID. Resolves it if needed
        """
        try:
            primarygroupid = int(entry['attributes']['primaryGroupID'])
        except (TypeError, KeyError):
            # Doesn't have a primarygroupid, means it is probably a Group instead of a user
            return
        try:
            group = self.addomain.groups[self.addomain.groups_dnmap[primarygroupid]]
            return group['principal']
        except KeyError:
            # Look it up
            # Construct group sid by taking the domain sid, removing the user rid and appending the group rid
            groupsid = '%s-%d' % ('-'.join(entry['attributes']['objectSid'].split('-')[:-1]), primarygroupid)
            group = self.addomain.objectresolver.resolve_sid(groupsid, use_gc=False)
            if group is None:
                logging.warning('Warning: Unknown primarygroupid %d', primarygroupid)
                return None
            resolved_entry = ADUtils.resolve_ad_entry(group)
            self.addomain.groups[group['attributes']['distinguishedName']] = resolved_entry
            self.addomain.groups_dnmap[primarygroupid] = group['attributes']['distinguishedName']
            return resolved_entry['principal']

    @staticmethod
    def add_user_properties(user, entry):
        props = user['Properties']
        # print entry
        # Is user enabled? Checked by seeing if the UAC flag 2 (ACCOUNT_DISABLED) is not set
        props['enabled'] = ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 2 == 0
        props['lastlogon'] = ADUtils.win_timestamp_to_unix(
            ADUtils.get_entry_property(entry, 'lastLogon', default=0, raw=True)
        )
        props['pwdlastset'] = ADUtils.win_timestamp_to_unix(
            ADUtils.get_entry_property(entry, 'pwdLastSet', default=0, raw=True)
        )
        props['serviceprincipalnames'] = ADUtils.get_entry_property(entry, 'servicePrincipalName', [])
        props['hasspn'] = len(props['serviceprincipalnames']) > 0
        props['displayname'] = ADUtils.get_entry_property(entry, 'displayName')
        props['email'] = ADUtils.get_entry_property(entry, 'mail')
        props['title'] = ADUtils.get_entry_property(entry, 'title')
        props['homedirectory'] = ADUtils.get_entry_property(entry, 'homeDirectory')
        props['description'] = ADUtils.get_entry_property(entry, 'description')
        props['userpassword'] = ADUtils.get_entry_property(entry, 'userPassword')
        props['admincount'] = ADUtils.get_entry_property(entry, 'adminCount', 0) == 1

    def enumerate_users(self):
        filename = 'users.json'

        # Should we include extra properties in the query?
        with_properties = 'objectprops' in self.collect
        acl = 'acl' in self.collect
        entries = self.addc.get_users(include_properties=with_properties, acl=acl)

        # If the logging level is DEBUG, we ident the objects
        if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
            indent_level = 1
        else:
            indent_level = None

        try:
            out = codecs.open(filename, 'w', 'utf-8')
        except:
            logging.warning('Could not write file: %s' % filename)
            return

        logging.debug('Writing users to file: %s' % filename)

        # Initialize json header
        out.write('{"users":[')

        num_entries = 0
        for entry in entries:
            resolved_entry = ADUtils.resolve_ad_entry(entry)
            user = {
                "Name": resolved_entry['principal'],
                "PrimaryGroup": self.get_primary_membership(entry),
                "Properties": {
                    "domain": self.addomain.domain,
                    "objectsid": entry['attributes']['objectSid'],
                    "highvalue": False,
                    "unconstraineddelegation": ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00080000 == 0x00080000
                }
            }

            if with_properties:
                MembershipEnumerator.add_user_properties(user, entry)
            self.addomain.users[entry['dn']] = resolved_entry
            if num_entries != 0:
                out.write(',')
            json.dump(user, out, indent=indent_level)
            num_entries += 1


        logging.info('Found %d users', num_entries)
        out.write('],"meta":{"type":"users","count":%d}}' % num_entries)

        logging.debug('Finished writing users')
        out.close()

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

        # If the logging level is DEBUG, we ident the objects
        if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
            indent_level = 1
        else:
            indent_level = None

        try:
            out = codecs.open(filename, 'w', 'utf-8')
        except:
            logging.warning('Could not write file: %s' % filename)
            return

        logging.debug('Writing groups to file: %s' % filename)

        # Initialize json header
        out.write('{"groups":[')

        num_entries = 0
        for entry in entries:
            resolved_entry = ADUtils.resolve_ad_entry(entry)
            self.addomain.groups[entry['dn']] = resolved_entry
            try:
                sid = entry['attributes']['objectSid']
            except KeyError:
                #Somehow we found a group without a sid?
                logging.warning('Could not determine SID for group %s' % entry['attributes']['distinguishedName'])
                continue
            group = {
                "Name": resolved_entry['principal'],
                "Properties": {
                    "domain": self.addomain.domain,
                    "objectsid": sid,
                    "highvalue": is_highvalue(sid)
                },
                "Members": []
            }
            if with_properties:
                group['Properties']['admincount'] = ADUtils.get_entry_property(entry, 'adminCount', default=0) == 1
                group['Properties']['description'] = ADUtils.get_entry_property(entry, 'description')

            for member in entry['attributes']['member']:
                resolved_member = self.get_membership(member)
                if resolved_member:
                    group['Members'].append(resolved_member)

            if num_entries != 0:
                out.write(',')
            json.dump(group, out, indent=indent_level)
            num_entries += 1


        logging.info('Found %d groups', num_entries)
        out.write('],"meta":{"type":"groups","count":%d}}' % num_entries)
        logging.debug('Finished writing groups')
        out.close()

    def enumerate_memberships(self):
        self.enumerate_users()
        self.enumerate_groups()
