import re
from typing import Literal
import sys
import os
import structlog
logger = structlog.get_logger('opentide.validation.legacy')

def indicator_validation(type: Literal['email', 'url', 'domain', 'ip', 'ip::v6', 'uuid', 'hash::md5', 'hash::sha1', 'hash::sha256', 'hash::sha512'], value, verbose: bool=True) -> bool:
    EMAIL_REGEX = '^([a-z0-9_\\.-]+\\@[\\da-z\\.-]+\\.[a-z\\.]{2,6})$'
    URL_REGEX = '(((ftp|http|https):\\/\\/)|(\\/)|(..\\/))(\\w+:{0,1}\\w*@)?(\\S+)(:[0-9]+)?(\\/|\\/([\\w#!:.?+=&%@!\\-\\/]))?'
    DOMAIN_REGEX = '(?=^.{1,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\\.)+[a-zA-Z]{2,63}$)'
    UUID_REGEX = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    IP_REGEX = '^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\\.(?!$)|$)){4}$'
    IPV6_REGEX = '^((([0-9A-Fa-f]{1,4}:){1,6}:)|(([0-9A-Fa-f]{1,4}:){7}))([0-9A-Fa-f]{1,4})$'
    HASH_REGEX = '^[a-fA-F0-9]{{{}}}$'
    match type:
        case 'email':
            if re.match(EMAIL_REGEX, value):
                return True
        case 'url':
            if re.match(URL_REGEX, value):
                return True
        case 'domain':
            if re.match(DOMAIN_REGEX, value):
                return True
        case 'ip':
            if re.match(IP_REGEX, value):
                return True
        case 'ip::v6':
            if re.match(IPV6_REGEX, value):
                return True
        case 'uuid':
            if re.match(UUID_REGEX, value):
                return True
        case 'hash::md5':
            if re.match(HASH_REGEX.format(32), value):
                return True
        case 'hash::sha1':
            if re.match(HASH_REGEX.format(40), value):
                return True
        case 'hash::sha256':
            if re.match(HASH_REGEX.format(64), value):
                return True
        case _:
            logger.critical('indicators_validation_received_invalid_type', arg0=type)
            raise Exception(' Invalid Type')
    if verbose:
        logger.error('operation_failed', detail=f'The following value is not of type {type}', arg0=value, advice='Correct the value to the expected type.')
    return False
