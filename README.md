# modsecurity-experiments

## Python + Django

* Compile mod-security in Debian 10 following the official [Dockerfile](https://github.com/coreruleset/modsecurity-docker/blob/master/v3-nginx/Dockerfile) steps

* Install [pymodsecurity](https://github.com/pymodsecurity/pymodsecurity)
** Remember to install pybind11 first - ``pip3 install pybind11``

* Install Django - ``pip3 install Django``

* Create a simple website - ``django-admin startproject mysite``

* Install the [pymodsec middleware example](https://github.com/pymodsecurity/django-pymodsecurity) - ``python3 setup.py install``

* Configure with the settings.py inside this repo and test Django app
** Check the basic rules, that blocks only when the req comes from 127.0.0.1 as an example
** Verify and tune modsecurity rules

## TODO

* Make a standalone simple HTTP Server that can use pymodsecurity
* Make a SPOE Server for HAProxy that can use pymodsecurity
* Check the logging
* Check if it's possible to inject SecRule Ignores during runtime (ignoring rules for each vhost)
* Check if it's possible to change the logformat and receive variables from the http server (like namespace from k8s)
