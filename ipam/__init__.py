import collections
import enum
import ctypes
import bisect
import socket

from . import nltypes


def remove_l(a, x, lo=None, hi=None):
    if None is hi:
        hi = len(a)
    if None is lo:
        lo = 0
    left = bisect.bisect_left(a, x, lo=lo, hi=hi)
    right = bisect.bisect_right(a, x, lo=left, hi=hi)
    if left < right:
        del a[left:right]
    return None


def add_l(a, x, lo=None, hi=None, update=True):
    if None is hi:
        hi = len(a)
    if None is lo:
        lo = 0
    left = bisect.bisect_left(a, x, lo=lo, hi=hi)
    right = bisect.bisect_right(a, x, lo=left, hi=hi)
    if left == right:
        a.insert(left, x)
    elif update and left < right:
        a[left] = x
        if 1 + left < right:
            del a[1 + left:right]
    return None


def filter_iter_link(link_list, index=None, ifname=None):
    yield from ((ifi, attr) for ifi, attr in link_list
                if None is index or ifi.ifi_index in index
                if None is ifname or (ctypes.string_at(attr[
                    nltypes.IFLA_IFNAME]).decode() in ifname))
    return None


def filter_iter_addr(addr_list, index=None, family=None):
    yield from ((ifa, attr) for ifa, attr in addr_list
                if None is index or ifa.ifa_index in index
                if None is family or ifa.ifa_family in family)
    return None


class comparer:
    __slots__ = ()

    def cmp(self, obj):
        if object.__gt__(self, obj):
            return 1
        if object.__lt__(self, obj):
            return 1

    def __eq__(self, obj):
        return self.cmp(obj) == 0

    def __lt__(self, obj):
        return self.cmp(obj) < 0

    def __le__(self, obj):
        return self.cmp(obj) <= 0

    def __gt__(self, obj):
        return self.cmp(obj) > 0

    def __ge__(self, obj):
        return self.cmp(obj) >= 0


def compare(a, b):
    if None is a or None is b:
        return (0 if None is a else 1) - (0 if None is b else 1)
    elif a > b:
        return 1
    elif a < b:
        return -1
    return 0


class _rtatb(tuple):
    __slots__ = ()

    def __contains__(self, obj):
        try:
            return None is not self[obj]
        except IndexError:
            pass
        return False

    def __repr__(self):
        return '{{{!s}}}'.format(', '.join('{!r}: {!r}'.format(i, v)
                                           for i, v in enumerate(self)
                                           if None is not v))

    def __new__(cls, size, rta, n):
        tb = [None] * size
        while nltypes.RTA_OK(rta, n):
            tb[rta.rta_type] = bytes(
                nltypes.RTA_DATA(rta,
                                 ctypes.c_ubyte * nltypes.RTA_PAYLOAD(rta)))
            rta, n = nltypes.RTA_NEXT(rta, n)
        return tuple.__new__(cls, tb)


_ifinfomsg = collections.namedtuple(
    'ifinfomsg',
    ('ifi_family', 'ifi_type', 'ifi_index', 'ifi_flags', 'ifi_change'))

_rtnl_link = collections.namedtuple('_rtnl_link', ('ifi', 'rta'))


class rtnl_link(comparer, _rtnl_link):
    __slots__ = ()

    def cmp(self, obj):
        diff = compare(self.ifi.ifi_index, obj.ifi.ifi_index)
        if 0 != diff:
            return diff
        return 0

    def __new__(cls, nlh):
        ifi = nltypes.NLMSG_DATA(nlh, nltypes.c_ifinfomsg)
        obj = _rtnl_link.__new__(
            cls,
            ifi=_ifinfomsg(ifi.ifi_family, ifi.ifi_type, ifi.ifi_index,
                           ifi.ifi_flags, ifi.ifi_change),
            rta=_rtatb(1 + nltypes.IFLA_MAX, nltypes.IFLA_RTA(ifi),
                       nltypes.IFLA_PAYLOAD(nlh)))
        return obj


_ifaddrmsg = collections.namedtuple(
    'ifaddrmsg',
    ('ifa_family', 'ifa_prefixlen', 'ifa_flags', 'ifa_scope', 'ifa_index'))

_rtnl_addr = collections.namedtuple('_rtnl_addr', ('ifa', 'rta'))


class rtnl_addr(comparer, _rtnl_addr):
    __slots__ = ()

    def cmp(self, obj):
        diff = compare(self.ifa.ifa_index, obj.ifa.ifa_index)
        if 0 != diff:
            return diff
        diff = compare(self.rta[nltypes.IFA_BROADCAST],
                       obj.rta[nltypes.IFA_BROADCAST])
        if 0 != diff:
            return -diff
        diff = compare(self.ifa.ifa_scope, obj.ifa.ifa_scope)
        if 0 != diff:
            return diff
        diff = compare(self.ifa.ifa_flags, obj.ifa.ifa_flags)
        if 0 != diff:
            return diff
        diff = compare(self.ifa.ifa_family, obj.ifa.ifa_family)
        if 0 != diff:
            return diff
        diff = compare(self.ifa.ifa_prefixlen, obj.ifa.ifa_prefixlen)
        if 0 != diff:
            return -diff
        diff = compare(self.rta[nltypes.IFA_ADDRESS],
                       obj.rta[nltypes.IFA_ADDRESS])
        if 0 != diff:
            return -diff
        return 0

    def __new__(cls, nlh):
        ifa = nltypes.NLMSG_DATA(nlh, nltypes.c_ifaddrmsg)
        obj = _rtnl_addr.__new__(
            cls,
            ifa=_ifaddrmsg(ifa.ifa_family, ifa.ifa_prefixlen, ifa.ifa_flags,
                           ifa.ifa_scope, ifa.ifa_index),
            rta=_rtatb(1 + nltypes.IFA_MAX, nltypes.IFA_RTA(ifa),
                       nltypes.IFA_PAYLOAD(nlh)))
        return obj
