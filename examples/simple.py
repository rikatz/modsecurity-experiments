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
import ModSecurity

modsec = None


class modsechandler(BaseHTTPRequestHandler):
    def _set_response(self, response):
        if isinstance(response, int) and response > 400:
            self.send_response(response)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write("ERROR".encode('utf-8'))
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write("OK".encode('utf-8'))

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n",
                     str(self.path), str(self.headers))

        response = self.call_modsec()
        self._set_response(response)

    def do_POST(self):
        response = self.call_modsec()
        self._set_response(response)

    def call_modsec(self):
        transaction = ModSecurity.Transaction(modsec.modsecurity, modsec.rules)
        transaction.processConnection(self.client_address[0],
                                      self.client_address[1],
                                      "127.0.0.1",
                                      80)
        response = self.process_intervention(transaction)
        if response is not None:
            return response

        httpversion = self.request_version.split('/', 2)[1]
        transaction.processURI(self.path, self.command, httpversion)
        response = self.process_intervention(transaction)
        if response is not None:
            return response

        for name, value in sorted(self.headers.items()):
            transaction.addRequestHeader(name, value)

        transaction.processRequestHeaders()
        response = self.process_intervention(transaction)
        if response is not None:
            return response

        length = self.headers['Content-Length']
        if length is not None and int(length) > 0:
            field_data = self.rfile.read(int(length))
            transaction.appendRequestBody(field_data)
            transaction.processRequestBody()
            response = self.process_intervention(transaction)
            if response is not None:
                return response

        return None

    def process_intervention(self, transaction):
        '''
        Check if there's interventions
        :return the apropriate response, if any:
        :rtype HttpResponse:
        '''
        intervention = ModSecurity.ModSecurityIntervention()
        if intervention is None:
            return None

        if transaction.intervention(intervention):
            if intervention.log is not None:
                logging.info(intervention.log)

            if not intervention.disruptive:
                return None

            if intervention.url is not None:
                response = 301
            else:
                response = 403

            return response
        else:
            return None


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


def run(port, rulefile):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    global modsec
    modsec = ModSec(rules=rulefile)
    logging.info("Loaded Modsecurity %s\n", modsec.modsecurity.whoAmI())
    httpd = HTTPServer(server_address, modsechandler)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')


if __name__ == '__main__':
    from sys import argv

    if len(argv) == 3:
        run(port=int(argv[1]), rulefile=argv[2])
    else:
        logging.fatal("Command must be called with port rule-file")
