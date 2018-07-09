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
import threading

class ObjectResolver(object):
    """
    This class is responsible for resolving objects. This can be for example sAMAccountNames which
    should be resolved in the GC to see which domain they belong to, or SIDs which have to be
    resolved somewhere else. This resolver is thread-safe.
    """
    def __init__(self, addomain, addc):
        self.addomain = addomain
        self.addc = addc
        self.lock = threading.Lock()

    def resolve_group(self, group):
        """
        Resolve a group DN in LDAP. This will use the GC
        """
        with self.lock:
            if not self.addc.gcldap:
                if not self.addc.gc_connect():
                    # Error connecting, bail
                    return None
            logging.debug('Querying GC for %s', group)
            group = self.addc.ldap_get_single(group)
            return group
