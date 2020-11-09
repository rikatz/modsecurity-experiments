# Mod security + python examples

* simple.py

    This script runs a simple httpserver and block or allow the request based on the loaded rules

    Syntax: simple.py port rule-file
    Ex.: simple.py 8080 block-localhost.conf
 
    This script parses only the request, and not the response


