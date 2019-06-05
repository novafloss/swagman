import argparse
import json
import os.path
import re
import sys

from collections import defaultdict
from string import Template

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = KeyError

try:
    import httplib
except ImportError:
    import http.client as httplib

import yaml


EXCL_HEADERS = [
    'Date',
    'Server',
    'X-Frame-Options',
]


def get_type(value):
    if isinstance(value, bool):
        return 'boolean'
    elif isinstance(value, int):
        return 'integer'
    elif isinstance(value, str) and value.isdigit():
        return 'integer'
    else:
        return 'string'


class CollectionTemplate(Template):
    delimiter = '{{'
    pattern = r'''
    \{\{(?:
    (?P<escaped>\{\{)|
    (?P<named>[_\-a-z][_\-a-z0-9]*)\}\}|
    (?P<braced>[_\-a-z][_\-a-z0-9]*)\}\}|
    (?P<invalid>)
    )
    '''


class CollectionContext(dict):

    def __init__(self, data):
        for item in (data.get('values') or []):
            if not item.get('enabled'):
                continue
            self[item['key']] = item['value']

    @classmethod
    def from_json(cls, data):
        try:
            return cls(json.loads(data))
        except JSONDecodeError as e:
            sys.stderr.write('Invalid collection context: {}\n'.format(e))
            sys.exit(1)

    @classmethod
    def from_file(cls, path):

        if not path:
            return cls()

        if not os.path.exists(path):
            sys.stderr.write("Can't find collection context: {}\n".format(path))
            sys.exit(1)

        with open(path) as in_file:
            return cls.from_json(in_file.read())


class AttrDict(dict):

   def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


class CollectionRequest(AttrDict):


    @property
    def body_dict(self):

        if not self.body:
            return {}

        mode = self.body['mode']
        body = self.body[mode]

        if mode == 'urlencoded':
            return {i['key']: i['value'] for i in body}

        elif body and mode == 'raw':
            return json.loads(body)

        else:
            return {}

    @property
    def body_parameters(self):

        body_parameters = []
        required = self.item.method in ['post', 'put']

        if 'application/x-www-form-urlencoded' in self.item.consumes:
            body_parameters += [
                {
                    'name': k,
                    'in': 'formData',
                    'description': '',
                    'required': required,
                    'type': get_type(v)
                }
                for k, v in self.body_dict.items()
            ]

        if any(c.startswith('application/json')
               for c in self.item.consumes):

            body_parameters.append({
                'name': 'body',
                'in': 'body',
                'description': '',
                'required': required,
                'schema': {
                    k: {
                        'type': get_type(v),
                        'description': '',
                    } for k, v in self.body_dict.items()
                }
            })

        return body_parameters

    @property
    def examples(self):

        if self.output_format == 'html':
            example = '<h3>Request</h3>\n'
        else:
            example = 'Request:\n\n'

        if self.output_format == 'html':
            example += '<pre>\n'

        example += '{} {} HTTP/1.1\n'.format(
            self.method,
            self.path
        )
        example += 'Authorization: {}\n'.format(
            self.get_header('Authorization')
        )
        example += 'Cotent-Type: {}\n'.format(
            self.get_header('Content-Type')
        )
        example += '\n'
        if self.body_dict:
            example += '{}\n'.format(json.dumps(self.body_dict, indent=2))

        if self.output_format == 'html':
            example += '</pre>\n'
        else:
            example += '\n'

        if self.output_format == 'html':
            example += '<h3>Response</h3>\n'
        else:
            example += 'Response:\n\n'

        if self.output_format == 'html':
            example += '<pre>\n'

        example += 'HTTP/1.1 {} {}\n'.format(
            self.response.code,
            self.response.status
        )

        content_type = self.get_response_header('Content-Type')
        if content_type:
            example += 'Cotent-Type: {}\n'.format(content_type)

        example += '\n'
        if self.response_body:
            example += '{}\n'.format(json.dumps(self.response_body, indent=2))

        if self.output_format == 'html':
            example += '</pre>\n'

        return {
            (content_type or 'application/json'): example
        }

    def get_headers(self, item, to_exclude=EXCL_HEADERS):
        return {
            header['key']: {'type': get_type(header['value']), 'description': header['value']}
            for header in (item.header or [])
            if header['key'] not in (to_exclude or [])
        }

    def get_header(self, key):
        known_headers = self.get_headers(self).get(key)
        return known_headers.get('description', '') if isinstance(known_headers, dict) else ''

    def get_response_header(self, key):
        return self.get_headers(self.response).get(key).get('description', '')

    def get_response_property_description(self, name):
        return ''

    @property
    def headers(self):
        return self.get_headers(self)

    @property
    def path(self):
        basePath = self.item.collection_parser.basePath
        for host in self.item.collection_parser._hosts:
            if isinstance(self.url, dict):
                return '/'.join(self.url['path']).replace(basePath[1:], '')
            else:
                return self.url.replace('{}{}'.format(host, basePath), '')

    @property
    def response_body(self):

        if 'body' not in self.response:
            return {}

        try:
            body = json.loads(self.response.body or '{}')
        except JSONDecodeError:
            sys.stderr.write('Invalid body: {}\n'.format(self.response.body))
            sys.exit(1)

        if isinstance(body, list):
            body = body[0]

        return body

    @property
    def response_headers(self):
        return self.get_headers(self.response)

    @property
    def response_schema_properties(self):
        return {
            k: {
                'type': get_type(v),
                'description': self.get_response_property_description(k),
            } for k, v in self.response_body.items()
       }


class CollectionExecutionRequestList(list):

    def __init__(self, collection_parser, item):
        self.item = item
        for _exec in collection_parser.executions:
            if _exec['item']['request']['url'] != item['request']['url']\
                    or _exec['item']['request']['method'].lower() != item['request']['method'].lower():  # noqa
                continue
            self.append(CollectionRequest(
                dict(
                    _exec['request'],
                    item=item,
                    output_format=collection_parser.output_format,
                    response=AttrDict(_exec['response'])
                )
            ))

    def get_request(self, *codes):
        for request in self:
            if request.response.code in codes:
                return request
        return {}

    def get_response(self, *codes):
        for request in self:
            if request.response.code in codes:
                return request.response
        return {}

    @property
    def content_types(self):
        return list(set(filter(None, [
            request.get_response_header('Content-Type')
            for request in self
        ])))

    @property
    def response(self):
        return self.get_response(200, 201, 204)

    @property
    def request(self):
        return self.get_request(200, 201, 204)

    @property
    def path_parameters(self):

        if not isinstance(self.item.url, dict):
            return []

        parameters = self.item.url.get('variable') or []

        return [
            {
                'name': p['id'],
                'in': 'path',
                'description': '',
                'required': True,
                'type': get_type(p['value'])
            }
            for p in parameters
        ]

    @property
    def query_parameters(self):

        parts = self.item.url.split('?')

        if len(parts) < 2:
            return []

        params = dict([i.split('=') for i in parts[1].split('&')])

        return [
            {
                'name': k,
                'in': 'query',
                'description': '',
                'required': False,
                'type': get_type(v)
            }
            for k, v in params.items()
        ]

    @property
    def swagger_parameters(self):

        body_parameters = [
            dict(p, required=True)
            for p in (self.request.get('body_parameters') or [])
        ]

        for request in self:
            for param in request.body_parameters:
                if any(param['name'] == p['name'] for p in body_parameters):
                    continue
                body_parameters.append(param)

        path_parameters = self.path_parameters
        query_parameters = self.query_parameters

        return body_parameters + path_parameters + query_parameters

    @property
    def swagger_responses(self):

        swagger_responses = {}

        for request in self:

            swagger_responses[request.response.code] = {
                'description': httplib.responses.get(request.response.code, ''),
                'examples': request.examples,
                'headers': request.response_headers,
                'schema': {
                    'type': 'object',
                    'properties': request.response_schema_properties,
                },
            }

        return swagger_responses


class CollectionItemParser(dict):

    _auth_header = None
    _execution_requests = None
    _url = None

    def __init__(self, collection_parser, item):
        super(CollectionItemParser, self).__init__(item)
        self.collection_parser = collection_parser

    @property
    def auth_header(self):

        if self._auth_header:
            return self._auth_header

        for header in (self.request.header if hasattr(self.request, 'header') else []):
            if header['key'] != 'Authorization'\
                    or not header['value'].startswith('Bearer '):
                continue
            self._auth_header = header

        return self._auth_header

    @property
    def consumes(self):
        return list(filter(None, [self.header.get('Content-Type')]))

    @property
    def description(self):
        return self.request.get('description', {}).get('content')

    @property
    def execution_requests(self):
        if not self._execution_requests:
            self._execution_requests = CollectionExecutionRequestList(
                self.collection_parser, self
            )
        return self._execution_requests

    @property
    def header(self):
        return {
            h['key']:h['value']
            for h in (self.request.header if hasattr(self.request, 'header') else [])
        }

    @property
    def method(self):
        method = self.get('request', {}).get('method')
        if not method:
            sys.stderr.write('Missing request method\n')
            sys.exit(1)
        return method.lower()

    @property
    def operationId(self):
        return self.url[1:]\
            .replace('/', '-')\
            .replace(':', '')

    @property
    def parameters(self):
        return self.execution_requests.swagger_parameters

    @property
    def produces(self):
        return self.execution_requests.content_types

    @property
    def request(self):
        return CollectionRequest(self.get('request') or {})

    @property
    def response_code(self):

        response_code = self.execution_requests.response.code

        if response_code:
            return response_code

        elif self.method == 'post':
            return 201

        elif self.method == 'delete':
            return 204

        return 200

    @property
    def responses(self):
        return self.execution_requests.swagger_responses

    @property
    def security(self):

        auth = self.request.get('auth') or {}
        auth_type = auth.get('type')

        if auth_type == 'basic':
            return [{'basic': []}]

        if self.auth_header\
                and self.auth_header['value'].startswith('Bearer '):
            return [{'api_key': []}]

        return []

    @property
    def tags(self):
        tags = [t for t in self.url.split('/')[1:] if not (t.startswith(':') or t.startswith('{') or t.endswith('}'))]
        # Tags should not have duplicate items, see https://swagger.io/specification/v2/
        return list({i for i in sorted(self.collection_parser.extra_tags + tags) if i})

    @property
    def url(self):

        if self._url:
            return self._url

        url = self.request.url

        if isinstance(url, dict) and 'raw' in url:
            url = url['raw']

        if isinstance(url, dict) and 'host' in url:
            url = '{}/{}'.format(
                url['host'][0],
                '/'.join(url['path'])
            )

        for host in self.collection_parser._hosts:
            self._url = url.replace(
                '{}{}'.format(host, self.collection_parser.basePath),
                ''
            ).split('?')[0]
            return self._url


class CollectionParser(dict):

    basePath = '/'
    host = None
    output_format = None

    _executions = None
    _extra_tags = None
    _schemes = None

    _consumes = None
    _produces = None
    _security = None
    _security_definitions = None

    @property
    def _hosts(self):
        if not self.host:
            return []
        return ['{}://{}'.format(s, self.host) for s in self.schemes]

    @property
    def consumes(self):
        return list(sorted(self._consumes))

    @property
    def executions(self):
        return self._executions or []

    @executions.setter
    def executions(self, executions):
        if not isinstance(executions, list):
            sys.stderr.write('Invalid report executions\n')
            sys.exit(1)
        self._executions = executions

    @property
    def extra_tags(self):
        return self._extra_tags or []

    @extra_tags.setter
    def extra_tags(self, extra_tags):
        if not isinstance(extra_tags, list):
            sys.stderr.write('Invalid extra tags\n')
            sys.exit(1)
        self._extra_tags = extra_tags

    @property
    def paths(self):

        paths = {}

        self._consumes = []
        self._produces = []
        self._security = {}
        self._security_definitions = {}

        collection_items = []

        for item in self.get('item', []):
            if 'item' in item:
                collection_items += item['item']
            else:
                collection_items.append(item)

        for item in collection_items:

            item_parser = CollectionItemParser(self, item)

            if not item_parser.url:
                continue

            if item_parser.method in paths.get(item_parser.url, {}):
                continue

            if item_parser.url not in paths:
                paths[item_parser.url] = {}

            consumes = item_parser.consumes
            produces = item_parser.produces
            security = item_parser.security

            paths[item_parser.url][item_parser.method] = {
                'consumes': consumes,
                'description': item_parser.description or '',
                'operationId': item_parser.operationId,
                'produces': produces,
                'parameters': item_parser.parameters,
                'responses': item_parser.responses,
                'security': security,
                'tags': item_parser.tags,
            }

            self._consumes = list(set(self._consumes + consumes))
            self._produces = list(set(self._produces + produces))

            if not security:
                continue

            security_name = list(security[0].keys())[0]

            self._security[security_name] = []

            if security_name in self._security_definitions:
                continue

            description = (item_parser.auth_header or {})\
                .get('description', {})\
                .get('content') or ''

            _type = 'apiKey' if security_name == 'api_key' else 'basic'

            self._security_definitions[security_name] = {
                'description': description,
                'in': 'header',
                'name': 'access_token',
                'type': _type,
            }

        return paths

    @property
    def produces(self):
        return list(sorted(self._produces))

    @property
    def schemes(self):
        if not self._schemes:
            self._schemes = ['https']
        return self._schemes

    @schemes.setter
    def schemes(self, schemes):
        if not isinstance(schemes, list):
            sys.stderr.write('Invalid schemes list\n')
            sys.exit(1)
        self._schemes = schemes

    @property
    def security(self):
        return self._security

    @property
    def security_definitions(self):
        return self._security_definitions

    @property
    def title(self):
        return self.get('info', {}).get('name', '')

    @classmethod
    def from_json(cls, data, environment=None, _globals=None):
        try:

            environment = environment or {}
            _globals = _globals or _globals

            content = CollectionTemplate(data).safe_substitute(
                **dict(_globals, **environment)
            )

            collection_or_report = json.loads(content)

            collection = collection_or_report.get('collection')\
                or collection_or_report

            collection_parser = cls(collection)

            executions = collection_or_report.get('run', {}).get('executions')\
                or []

            collection_parser.executions = executions

            return collection_parser

        except JSONDecodeError as e:
            sys.stderr.write('Invalid collection: {}\n'.format(e))
            sys.exit(1)

    @classmethod
    def from_file(cls, path, environment=None, _globals=None):

        if not path:
            return cls()

        if not os.path.exists(path):
            sys.stderr.write("Can't find collection: {}\n".format(path))
            sys.exit(1)

        with open(path) as in_file:
            return cls.from_json(in_file.read(), environment=environment,
                                 _globals=_globals)


class Swagger(dict):

    @classmethod
    def from_collection_parser(cls, collection_parser):
        return Swagger({
            'swagger': '2.0',
            'info': {
                'title': collection_parser.title,
                'version': '',
            },
            # from command line, default: /
            'basePath': collection_parser.basePath,
            # from command line
            'host': collection_parser.host,
            'paths': collection_parser.paths,
            # consumes & produces generated by collection_parser.paths call
            'consumes': collection_parser.consumes,
            'produces': collection_parser.produces,
            # from command line, default: ['https']
            'schemes': collection_parser.schemes,
            'security': collection_parser.security,
            'securityDefinitions': collection_parser.security_definitions,
        })

    def to_file(self, path, output_format='yaml', template_path=None):
        with open(path, 'w') as out_file:
            if output_format == 'yaml':
                out_file.write(self.to_yaml())
            elif output_format == 'json':
                out_file.write(self.to_json())
            elif output_format == 'html':
                out_file.write(self.to_html(template_path))
            else:
                pass

    def to_html(self, template_path):

        if not template_path or not os.path.exists(template_path):
            sys.stderr.write('Template path not found: {}\n'.format(
                template_path
            ))
            sys.exit(1)

        try:
            import jinja2
        except ImportError:
            sys.stderr.write('Missing jinja2 requirement.\n')
            sys.exit(1)

        template_dir, template_name = os.path.split(
            os.path.abspath(template_path)
        )

        jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            lstrip_blocks=True,
            trim_blocks=True,
            undefined=jinja2.StrictUndefined,
        )

        template = jinja_env.get_template(template_name)

        return template.render(**dict(self)).encode('utf-8')

    def to_json(self):
        return json.dumps(dict(self), indent=2)

    def to_yaml(self):
        return yaml.safe_dump(dict(self), default_flow_style=False)


def parse_args():

    parser = argparse.ArgumentParser(
        description='Convert PostMan Collections to Swagger file.',
    )

    parser.add_argument(
        'input',
        help='Path to the collection to convert',
        type=str,
    )

    parser.add_argument(
        '-b',
        '--base-path',
        default='/',
        dest='basePath',
        help='Base path to a collection, ex: /api, default: /',
        type=str,
    )

    parser.add_argument(
        '-e',
        '--environment',
        default=None,
        help='Path to a collection environment file, default: None',
        type=str,
    )

    parser.add_argument(
        '-f',
        '--output-format',
        default='yaml',
        help='Output format between json or yaml, default: yaml',
        type=str,
    )

    parser.add_argument(
        '-g',
        '--globals',
        default=None,
        dest='_globals',
        help='Path to a collection globals file, default: None',
        type=str,
    )

    parser.add_argument(
        '-H',
        '--host',
        default=None,
        help='Host of the collection file, ex.: 127.0.0.1, default: None',
        type=str,
    )

    parser.add_argument(
        '-o',
        '--output',
        default='swagger.yml',
        help='Path to the swagger file to generate, default: swagger.yml',
        type=str,
    )

    parser.add_argument(
        '-s',
        '--schemes',
        default='https',
        help='Supported schemes of the collection file, ex.: "http,https", '
             'default: https',
        type=str,
    )

    parser.add_argument(
        '-t',
        '--extra-tags',
        default='',
        help='Additional tags to be included, ex: "sso,oauth", default: ""',
        type=str,
    )

    parser.add_argument(
        '--template',
        default=None,
        dest='template_path',
        help='Path to a template to use for swagger result rendering '
             '(required for html ouput).',
        type=str,
    )

    return parser.parse_args()


def main():
    args = parse_args()

    environment = CollectionContext.from_file(args.environment)
    _globals = CollectionContext.from_file(args._globals)

    collection_parser = CollectionParser.from_file(
        args.input,
        environment=environment,
        _globals=_globals,
    )

    collection_parser.basePath = args.basePath
    collection_parser.host = args.host
    collection_parser.output_format = args.output_format
    collection_parser.schemes = args.schemes.split(',')

    collection_parser.extra_tags = args.extra_tags.split(',')

    Swagger.from_collection_parser(collection_parser).to_file(
        args.output,
        output_format=args.output_format,
        template_path=args.template_path
    )

if __name__ == "__main__":
    main()
