import re
import sys
from ast import literal_eval
from base64 import b64encode

needs_base64 = re.compile('\\A[\\s:<]|[\0-\37\177]|\\s\\Z').search


def entry_string(entry):

    def handle_value(value):
        if isinstance(value, str) and needs_base64(value):
            value = str(b64encode(value.encode('utf-8')), 'utf-8')
            return f'{attr}:: {value}\n'
        else:
            return f'{attr}: {value}\n'

    result = ''
    for attr, value in entry.items():
        if isinstance(value, (list, tuple)):
            for val in value:
                result += handle_value(val)
        elif isinstance(value, (int, str)):
            result += handle_value(value)
        else:
            print(f'Unhandled value type {type(value)}, {value}')
            sys.exit(1)

    return result


def make_head_entry(cfg):
    head_entry = {}
    for attr, value in cfg.items('ldif'):
        # Convert a string tuple to an actual tuple
        if value.startswith('(') and value.endswith(')'):
            value = literal_eval(value)
        head_entry[attr] = value
    return head_entry
