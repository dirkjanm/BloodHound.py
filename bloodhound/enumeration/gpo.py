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

from itertools import count
import logging
import codecs
import json
import calendar
from os import access
from re import X
from turtle import position
from bloodhound.ad.utils import ADUtils, AceResolver
from bloodhound.ad.trusts import ADDomainTrust
from bloodhound.enumeration.acls import parse_binary_acl

class GpoEnumerator(object):

    """
    Class to enumerate GPO.
    """
    
    def __init__(self, addomain, addc):

        self.addomain = addomain
        self.addc = addc
        

    def dump_gpos(self, collect, timestamp="", filename='gpos.json'):
        

        filename = timestamp + filename
       
        if 'trusts' in collect:
            entries = self.addc.get_trusts()
        else:
            entries = []

        try:
            logging.debug('Opening file for writing: %s' % filename)
            out = codecs.open(filename, 'w', 'utf-8')
        except:
            logging.warning('Could not write file: %s' % filename)
            return

        if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
            indent_level = 1
        else:
            indent_level = None

        domain_object = None
        for domain in self.addomain.domains.keys():
            if domain.lower() == self.addomain.baseDN.lower():
                domain_object = self.addomain.domains[domain]
                break
        
        if not domain_object:
            logging.error('Could not find domain object. Aborting domain enumeration')
            return
        # Initialize json structure
        datastruct = {
            "data": [],
            "meta": {
                "type": "gpos",
                "count": 1,
                "version":5
            }
        }
        level_id = ADUtils.get_entry_property(domain_object, 'msds-behavior-version')
        try:
            functional_level = ADUtils.FUNCTIONAL_LEVELS[int(level_id)]
        except KeyError:
            functional_level = 'Unknown'

        whencreated = ADUtils.get_entry_property(domain_object, 'whencreated', default=0)
        if not isinstance(whencreated, int):
            whencreated = calendar.timegm(whencreated.timetuple())
        
        gpos = self.addc.get_gpo()
        count = 0
        for cant in gpos:
            count +=1
        datastruct['meta']['count'] = count
        gpos = self.addc.get_gpo()
        for gpo in gpos:
            attributes = gpo["attributes"]
            display = attributes["displayName"].upper()
            objectidentifier = attributes["objectGUID"].upper()
            objectidentifier = str(objectidentifier)
            objectidentifier = objectidentifier.replace('{', '')
            objectidentifier = objectidentifier.replace('}', '')
            gpcpath = attributes["gPCFileSysPath"]
            description = attributes["description"]
            if len(description) == 0:
                description = "Null"
            distin = gpo["dn"]
            whencreatedgpo = attributes["whenCreated"]
            whencreatedgpo = calendar.timegm(whencreatedgpo.timetuple())
            domain = {
                "Properties": {
                    "domain": self.addomain.domain.upper(),
                    "name": display + "@" + self.addomain.domain.upper(),
                    "distinguishedname": distin,
                    "domainsid": ADUtils.get_entry_property(domain_object, 'objectSid'),
                    "highvalue": False,
                    "description": description,
                    "whencreated": whencreatedgpo,
                    "gpcpath": gpcpath,
                },
                "Aces": [],
                "ObjectIdentifier": objectidentifier,
                "IsDeleted": False,
            }

            if 'acl' in collect:
                resolver = AceResolver(self.addomain, self.addomain.objectresolver)
                _, aces = parse_binary_acl(domain, 'domain', ADUtils.get_entry_property(domain_object, 'nTSecurityDescriptor'), self.addc.objecttype_guid_map)
                acces = []
                for value in aces:
                    if len(value["sid"]) > 16:
                        acces.append(value)
                domain['Aces'] = resolver.resolve_aces(acces)
                
            datastruct['data'].append(domain)
        
        json.dump(datastruct, out, indent=indent_level)

        logging.debug('Finished writing domain info')
        out.close()
