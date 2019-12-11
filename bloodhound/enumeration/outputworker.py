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

class OutputWorker(object):
    @staticmethod
    def write_worker(result_q, computers_filename):
        """
            Worker to write the results from the results_q to the given files.
        """
        computers_out = codecs.open(computers_filename, 'w', 'utf-8')

        # If the logging level is DEBUG, we ident the objects
        if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
            indent_level = 1
        else:
            indent_level = None

        # Write start of the json file
        computers_out.write('{"computers":[')
        num_computers = 0
        while True:
            obj = result_q.get()

            if obj is None:
                logging.debug('Write worker obtained a None value, exiting')
                break

            objtype, data = obj
            if objtype == 'computer':
                if num_computers != 0:
                    computers_out.write(',')
                json.dump(data, computers_out, indent=indent_level)
                num_computers += 1
            else:
                logging.warning("Type is %s this should not happen", objtype)

            result_q.task_done()

        logging.debug('Write worker is done, closing files')
        # Write metadata manually
        computers_out.write('],"meta":{"type":"computers","count":%d, "version":3}}' % num_computers)
        computers_out.close()
        result_q.task_done()

    @staticmethod
    def membership_write_worker(result_q, enumtype, filename):
        """
            Worker to write the results from the results_q to the given file.
            This is for both users and groups
        """
        try:
            membership_out = codecs.open(filename, 'w', 'utf-8')
        except:
            logging.warning('Could not write file: %s', filename)
            result_q.task_done()
            return

        # If the logging level is DEBUG, we ident the objects
        if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
            indent_level = 1
        else:
            indent_level = None

        # Write start of the json file
        membership_out.write('{"%s":[' % enumtype)
        num_members = 0
        while True:
            data = result_q.get()

            if data is None:
                break

            if num_members != 0:
                membership_out.write(',')
            json.dump(data, membership_out, indent=indent_level)
            num_members += 1

            result_q.task_done()

        logging.info('Found %d %s', num_members, enumtype)
        # Write metadata manually
        membership_out.write('],"meta":{"type":"%s","count":%d, "version":3}}' % (enumtype, num_members))
        membership_out.close()
        result_q.task_done()
