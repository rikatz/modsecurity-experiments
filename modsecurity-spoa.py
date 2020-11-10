"""
HAProxy SPOA - Modsecurity and Python
This is a heavily Work in Progress
Run this with the spoa binary, like: 
RULES=modsec-rules.conf ./spoa -f modsecurity-spoa.py
"""
import logging
import os
import spoa
import ModSecurity


class modsectransaction():
    def __init__(self, args):
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
            # TODO: Receive additional rulesIDs to be ignored

    def isvalid(self):
        valid = (
            hasattr(self, 'url')
            and hasattr(self, 'method')
            and hasattr(self, 'path')
            and hasattr(self, 'query')
            and hasattr(self, 'reqver')
            and hasattr(self, 'clientip')
            and hasattr(self, 'reqhdrs')
            and hasattr(self, 'reqbody')
        )
        return valid

    def call_modsec(self):
        # TODO: Can this be configurable? (The SPOE send the information)
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
        TODO: Parse headers
        for name, value in sorted(self.headers.items()):
            transaction.addRequestHeader(name, value)
        '''
        self.transaction.processRequestHeaders()
        response = self.process_intervention(self.transaction)
        if response > 0:
            return 1

        '''
        TODO: Parse body
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
    if transaction.isvalid():
        response = transaction.call_modsec()
    else:
        # TODO: Turn this configurable instead of default denying
        logging.warning("Received an invalid request, denying")
        response = 1

    spoa.set_var_int32("intervention", spoa.scope_sess, response)


logging.basicConfig(level=logging.INFO)
rulefile = os.environ.get('RULES')
global modsec
modsec = ModSec(rules=rulefile)
logging.info("Loaded Modsecurity %s\n", modsec.modsecurity.whoAmI())
spoa.register_message("modsecurity", modsecurity)
