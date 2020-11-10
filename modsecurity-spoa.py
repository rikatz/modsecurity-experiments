"""
Very simple HTTP server in python for logging requests
and using modsecurity
Usage::
    ./server.py <port> <rules-file>

This was based in the following projects/references:
* https://gist.githubusercontent.com/mdonkers/63e115cc0c79b4f6b8b3a6b797e485c7/raw/a6a1d090ac8549dac8f2bd607bd64925de997d40/server.py
* https://github.com/pymodsecurity/django-pymodsecurity
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import os
import spoa
from pprint import pprint
import ModSecurity


class modsectransaction():
    def __init__(self, args):
        logging.info("Building the object")
        # We create a new self.rules so we can add the IgnoreRules here
        self.rules = modsec.rules
        self.modsec = modsec.modsecurity
        self.transaction = ModSecurity.Transaction(self.modsec, self.rules)
        for obj in args:
            # TODO: There's for sure a less stupid way of doing this
            if obj['name'] == 'url':
                self.url = obj['value']
                continue
            if obj['name'] == 'method':
                self.method = obj['value']
                continue
            if obj['name'] == 'path':
                self.path = obj['value']
                continue
            if obj['name'] == 'query':
                self.query = obj['value']
                continue
            if obj['name'] == 'reqver':
                self.reqver = obj['value']
                continue
            if obj['name'] == 'ip':
                self.clientip = str(obj['value'])
                continue
            if obj['name'] == 'reqhdrs':
                # TODO: Create a method to convert this to the expected array
                self.reqhdrs = obj['value']
                continue
            if obj['name'] == 'reqbody':
                # TODO: Should this be parsed?
                self.reqbody = obj['value']
                continue
        # TODO: Validate if all the required fields are here

    def call_modsec(self):
        logging.info("Start transaction")
        self.transaction.processConnection(self.clientip,
                                           12345,
                                           "127.0.0.1",
                                           11111)
        response = self.process_intervention(self.transaction)
        if response > 0:
            return 1

        # TODO: url = self.url + self.query
        self.transaction.processURI(self.url, self.method, self.reqver)
        response = self.process_intervention(self.transaction)
        if response > 0:
            return 1
        '''
        for name, value in sorted(self.headers.items()):
            transaction.addRequestHeader(name, value)
        '''
        self.transaction.processRequestHeaders()
        response = self.process_intervention(self.transaction)
        if response > 0:
            return 1

        '''
        length = self.headers['Content-Length']
        if length is not None and int(length) > 0:
            field_data = self.rfile.read(int(length))
            transaction.appendRequestBody(field_data)
            transaction.processRequestBody()
            response = self.process_intervention(transaction)
            if response is not None:
                return response
        '''
        return 0

    def process_intervention(self, transaction):
        '''
        Check if there's interventions
        : return the apropriate response, if any:
        : rtype HttpResponse:
        '''
        intervention = ModSecurity.ModSecurityIntervention()
        if intervention is None:
            return 0

        if transaction.intervention(intervention):
            if intervention.log is not None:
                logging.info(intervention.log)

            if not intervention.disruptive:
                return 0

            # TODO: Deal with response redirection (see the django framework)
            '''
            if intervention.url is not None:
                response = 1
            else:
                response = 0
            '''
            return 1
        else:
            return 0


class ModSec():
    def __init__(self, rules):
        self.logger = logging.getLogger(__name__)
        self.modsecurity = ModSecurity.ModSecurity()
        self.modsecurity.setServerLogCb(self.modsecurity_log_callback)
        self.rules = ModSecurity.Rules()
        self.load_rule_files(rules)

    def modsecurity_log_callback(self, data, msg):
        self.logger.info(msg)

    def load_rule_files(self, rule_file):
        rules_count = self.rules.loadFromUri(rule_file)
        if rules_count < 0:
            msg = '[ModSecurity] Error trying to load rule file %s. %s' % (
                rule_file, self.rules.getParserError())
            self.logger.warning(msg)


def modsecurity(args):
    transaction = modsectransaction(args)
    pprint(transaction.call_modsec())


logging.basicConfig(level=logging.INFO)
rulefile = os.environ.get('RULES')
global modsec
modsec = ModSec(rules=rulefile)
logging.info("Loaded Modsecurity %s\n", modsec.modsecurity.whoAmI())
spoa.register_message("modsecurity", modsecurity)
