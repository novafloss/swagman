SwagMan
=======

Convert PostMan Collection Report to Swagger file.

See: https://github.com/postmanlabs/newman#json-reporter-options


Install
-------

Just pip install it as usual:

.. code:: bash

    ~$ pip install swagman


Or pip install it in developement:

.. code:: bash

    ~/swagman$ pip install -e .


Usage
-----

Please just follow the help:

.. code:: bash

    ~$ swagman -h
    usage: swagman [-h] [-b BASEPATH] [-e ENVIRONMENT] [-f OUTPUT_FORMAT]
                  [-g _GLOBALS] [-H HOST] [-o OUTPUT] [-s SCHEMES]
                  [-t EXTRA_TAGS] [--template TEMPLATE_PATH]
                  input

    Convert PostMan Collections to Swagger file.

    positional arguments:
      input                 Path to the collection to convert

    optional arguments:
      -h, --help            show this help message and exit
      -b BASEPATH, --base-path BASEPATH
                            Base path to a collection, ex: /api, default: /
      -e ENVIRONMENT, --environment ENVIRONMENT
                            Path to a collection environment file, default: None
      -f OUTPUT_FORMAT, --output-format OUTPUT_FORMAT
                            Output format between json or yaml, default: yaml
      -g _GLOBALS, --globals _GLOBALS
                            Path to a collection globals file, default: None
      -H HOST, --host HOST  Host of the collection file, ex.: 127.0.0.1, default:
                            None
      -o OUTPUT, --output OUTPUT
                            Path to the swagger file to generate, default:
                            swagger.yml
      -s SCHEMES, --schemes SCHEMES
                            Supported schemes of the collection file, ex.:
                            "http,https", default: https
      -t EXTRA_TAGS, --extra-tags EXTRA_TAGS
                            Additional tags to be included, ex: "sso,oauth",
                            default: ""
      --template TEMPLATE_PATH
                            Path to a template to use for swagger result rendering
                            (required for html ouput).


License
-------

MIT License
