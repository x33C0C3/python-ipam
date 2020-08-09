__all__ = ('iterencode_addrinfo', 'iterencode_linkinfo', 'iterencode')

import itertools
import functools

from . import utils

INFINITY_LIFE_TIME = 0xFFFFFFFF


def iterencode_addrinfo(addrinfo, brief=False):
    if not brief:
        if 'family' in addrinfo:
            yield '    {!s} '.format(addrinfo['family'])
        elif 'family_index' in addrinfo:
            yield '    family {!s} '.format(addrinfo['family_index'])
    if 'local' in addrinfo:
        yield '{!s}'.format(addrinfo['local'])
        if 'address' in addrinfo:
            yield ' peer '
            yield '{!s}'.format(addrinfo['address'])
        if 'prefixlen' in addrinfo:
            yield '/{!s} '.format(addrinfo['prefixlen'])
        if 'metric' in addrinfo:
            yield 'metric {!s} '.format(addrinfo['metric'])
    if brief:
        return None
    if 'broadcast' in addrinfo:
        yield 'brd '
        yield '{!s} '.format(addrinfo['broadcast'])
    if 'anycast' in addrinfo:
        yield 'any '
        yield '{!s} '.format(addrinfo['anycast'])
    if 'scope' in addrinfo:
        yield 'scope {!s} '.format(addrinfo['scope'])
    if addrinfo.get('dynamic'):
        yield 'dynamic '
    if addrinfo.get('temporary'):
        yield 'temporary '
    for flag_name in utils.ifa_flag_names.values():
        if addrinfo.get(flag_name):
            yield '{!s} '.format(flag_name)
    if 'ifa_flags' in addrinfo:
        yield 'flags {!s} '.format(addrinfo['ifa_flags'])
    if 'label' in addrinfo:
        yield '{!s}'.format(addrinfo['label'])
    if 'valid_life_time' in addrinfo and 'preferred_life_time' in addrinfo:
        yield '\n'
        yield '       valid_lft '
        if INFINITY_LIFE_TIME == addrinfo['valid_life_time']:
            yield 'forever'
        else:
            yield '{!s}sec'.format(addrinfo['valid_life_time'])
        yield ' preferred_lft '
        if INFINITY_LIFE_TIME == addrinfo['preferred_life_time']:
            yield 'forever'
        else:
            yield '{!s}sec'.format(addrinfo['preferred_life_time'])
    return None


def iterencode_linkinfo_brief(linkinfo, brief=False):
    yield '{!s:16} '.format(linkinfo['ifname'])
    if 'operstate_index' in linkinfo:
        yield 'state {!s} '.format(linkinfo['operstate_index'])
    elif 'operstate' in linkinfo:
        yield '{!s:14} '.format(linkinfo['operstate'])
    yield from itertools.chain.from_iterable(
        map(
            functools.partial(iterencode_addrinfo, brief=brief),
            linkinfo.get('addr_info', ())))
    return None


def iterencode_linkinfo(linkinfo, brief=False):
    if brief:
        return (yield from iterencode_linkinfo_brief(linkinfo, brief))
    yield '{!s}: '.format(linkinfo['ifindex'])
    yield '{!s}: '.format(linkinfo['ifname'])
    yield '<{!s}> '.format(','.join(linkinfo['flags']))
    if 'mtu' in linkinfo:
        yield 'mtu {!s} '.format(linkinfo['mtu'])
    if 'qdisc' in linkinfo:
        yield 'qdisc {!s} '.format(linkinfo['qdisc'])
    if 'master' in linkinfo:
        yield 'master {!s} '.format(linkinfo['master'])
    if 'operstate_index' in linkinfo:
        yield 'state {!s} '.format(linkinfo['operstate_index'])
    elif 'operstate' in linkinfo:
        yield 'state {!s} '.format(linkinfo['operstate'])
    if 'group' in linkinfo:
        yield 'group {!s} '.format(linkinfo['group'])
    if 'txqlen' in linkinfo:
        yield 'qlen {!s} '.format(linkinfo['txqlen'])
    if 'event' in linkinfo:
        yield 'event {!s} '.format(linkinfo['event'])
    yield '\n'
    yield '    link/{!s} '.format(linkinfo['link_type'])
    if 'address' in linkinfo:
        yield '{!s}'.format(linkinfo['address'])
    if 'broadcast' in linkinfo:
        if linkinfo.get('link_pointtopoint'):
            yield ' peer '
        else:
            yield ' brd '
        yield '{!s}'.format(linkinfo['broadcast'])
    yield '\n'
    yield from itertools.chain.from_iterable(
        itertools.islice(
            itertools.chain.from_iterable(
                zip(
                    itertools.repeat(('\n', )),
                    map(
                        functools.partial(iterencode_addrinfo, brief=brief),
                        linkinfo.get('addr_info', ())))), 1, None))
    return None


def iterencode(linkinfos, brief=False):
    yield from itertools.chain.from_iterable(
        itertools.islice(
            itertools.chain.from_iterable(
                zip(
                    itertools.repeat(('\n', )),
                    map(
                        functools.partial(iterencode_linkinfo, brief=brief),
                        linkinfos))), 1, None))
    return None
