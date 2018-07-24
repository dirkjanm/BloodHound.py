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
from ldap3.core.exceptions import LDAPKeyError
from bloodhound.ad.utils import ADUtils


class MembershipEnumerator(object):
    """
    Class to enumerate memberships in the domain.
    Contains the dumping functions which
    methods from the bloodhound.ad module.
    """
    def __init__(self, addomain, addc):
        """
        Membership enumeration. Enumerates all groups/users/other memberships.
        """
        self.addomain = addomain
        self.addc = addc

    def write_membership(self, resolved_entry, membership, out):
        if membership in self.addomain.groups:
            parent = self.addomain.groups[membership]
            pd = ADUtils.ldap2domain(membership)
            pr = ADUtils.resolve_ad_entry(parent)

            out.write(u'%s,%s,%s\n' % (pr['principal'], resolved_entry['principal'], resolved_entry['type']))
        else:
            # This could be a group in a different domain
            parent = self.addomain.objectresolver.resolve_group(membership)
            if not parent:
                logging.warning('Warning: Unknown group %s', membership)
                return
            self.addomain.groups[membership] = parent
            pd = ADUtils.ldap2domain(membership)
            pr = ADUtils.resolve_ad_entry(parent)

            out.write(u'%s,%s,%s\n' % (pr['principal'], resolved_entry['principal'], resolved_entry['type']))

    def write_primary_membership(self, resolved_entry, entry, out):
        try:
            primarygroupid = int(entry['attributes']['primaryGroupID'])
        except (TypeError, KeyError):
            # Doesn't have a primarygroupid, means it is probably a Group instead of a user
            return
        try:
            group = self.addomain.groups[self.addomain.groups_dnmap[primarygroupid]]
            pr = ADUtils.resolve_ad_entry(group)
            out.write('%s,%s,%s\n' % (pr['principal'], resolved_entry['principal'], resolved_entry['type']))
        except KeyError:
            logging.warning('Warning: Unknown primarygroupid %d', primarygroupid)

    def enumerate_memberships(self, filename='group_membership.csv'):
        entries = self.addc.get_memberships()

        try:
            logging.debug('Opening file for writing: %s' % filename)
            out = codecs.open(filename, 'w', 'utf-8')
        except:
            logging.warning('Could not write file: %s' % filename)
            return

        logging.debug('Writing group memberships to file: %s' % filename)

        out.write('GroupName,AccountName,AccountType\n')
        entriesNum = 0
        for entry in entries:
            entriesNum += 1
            resolved_entry = ADUtils.resolve_ad_entry(entry)
            try:
                for m in entry['attributes']['memberOf']:
                    self.write_membership(resolved_entry, m, out)
            except (KeyError, LDAPKeyError):
                logging.debug(traceback.format_exc())
            self.write_primary_membership(resolved_entry, entry, out)

        logging.info('Found %d memberships', entriesNum)
        logging.debug('Finished writing membership')
        out.close()
