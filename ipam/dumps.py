__all__ = ('encode_link', 'encode_addr', 'iterencode')

import ctypes

from . import nltypes
from . import utils


def encode_link(link, link_attr, flags=0, seq=0):
    nlmsg_len = nltypes.NLMSG_LENGTH(ctypes.sizeof(nltypes.c_ifinfomsg)) + sum(
        nltypes.RTA_SPACE(len(data)) for data in link_attr if None is not data)
    buf = (ctypes.c_ubyte * nlmsg_len)()
    nlh = nltypes.c_nlmsghdr.from_buffer(buf)
    nlh.nlmsg_len = nlmsg_len
    nlh.nlmsg_type = nltypes.RTM_NEWLINK
    nlh.nlmsg_flags = flags
    nlh.nlmsg_seq = seq
    n = nltypes.IFLA_PAYLOAD(nlh)
    ifm = nltypes.NLMSG_DATA(nlh, nltypes.c_ifinfomsg)
    ifm.ifi_family = link.ifi_family
    ifm.ifi_type = link.ifi_type
    ifm.ifi_index = link.ifi_index
    ifm.ifi_flags = link.ifi_flags
    ifm.ifi_change = link.ifi_change
    rta = nltypes.IFLA_RTA(ifm)
    for i, data in enumerate(link_attr):
        if None is not data:
            rta.rta_len = nltypes.RTA_LENGTH(len(data))
            rta.rta_type = i
            if not nltypes.RTA_OK(rta, n):
                raise ValueError
            nltypes.RTA_DATA(
                rta, (ctypes.c_ubyte * nltypes.RTA_PAYLOAD(rta)))[:] = data
            rta, n = nltypes.RTA_NEXT(rta, n)
    return bytes(buf)


def encode_addr(addr, addr_attr, flags=0, seq=0):
    nlmsg_len = nltypes.NLMSG_LENGTH(ctypes.sizeof(nltypes.c_ifaddrmsg)) + sum(
        nltypes.RTA_SPACE(len(data)) for data in addr_attr if None is not data)
    buf = (ctypes.c_ubyte * nlmsg_len)()
    nlh = nltypes.c_nlmsghdr.from_buffer(buf)
    nlh.nlmsg_len = nlmsg_len
    nlh.nlmsg_type = nltypes.RTM_NEWADDR
    nlh.nlmsg_flags = flags
    nlh.nlmsg_seq = seq
    n = nltypes.IFA_PAYLOAD(nlh)
    ifm = nltypes.NLMSG_DATA(nlh, nltypes.c_ifaddrmsg)
    ifm.ifa_family = addr.ifa_family
    ifm.ifa_prefixlen = addr.ifa_prefixlen
    ifm.ifa_flags = addr.ifa_flags
    ifm.ifa_scope = addr.ifa_scope
    ifm.ifa_index = addr.ifa_index
    rta = nltypes.IFA_RTA(ifm)
    for i, data in enumerate(addr_attr):
        if None is not data:
            rta.rta_len = nltypes.RTA_LENGTH(len(data))
            rta.rta_type = i
            if not nltypes.RTA_OK(rta, n):
                raise ValueError
            nltypes.RTA_DATA(
                rta, (ctypes.c_ubyte * nltypes.RTA_PAYLOAD(rta)))[:] = data
            rta, n = nltypes.RTA_NEXT(rta, n)
    return bytes(buf)


def iterencode(link_list,  addr_list):
    for link, link_attr in link_list:
        yield encode_link(link, link_attr)
    for addr, addr_attr in addr_list:
        yield encode_addr(addr, addr_attr)
    return None
