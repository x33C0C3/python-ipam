__all__ = ('iter_linkinfo', 'iter_addrinfo')

import ctypes
import socket

from . import filter_iter_link, filter_iter_addr
from . import nltypes

link_types = {
    nltypes.ARPHRD_ETHER: 'ether',
    nltypes.ARPHRD_EETHER: 'eether',
    nltypes.ARPHRD_AX25: 'ax25',
    nltypes.ARPHRD_PRONET: 'pronet',
    nltypes.ARPHRD_CHAOS: 'chaos',
    nltypes.ARPHRD_IEEE802: 'ieee802',
    nltypes.ARPHRD_ARCNET: 'arcnet',
    nltypes.ARPHRD_APPLETLK: 'atalk',
    nltypes.ARPHRD_DLCI: 'dlci',
    nltypes.ARPHRD_ATM: 'atm',
    nltypes.ARPHRD_METRICOM: 'metricom',
    nltypes.ARPHRD_IEEE1394: 'ieee1394',
    nltypes.ARPHRD_INFINIBAND: 'infiniband',
    nltypes.ARPHRD_SLIP: 'slip',
    nltypes.ARPHRD_CSLIP: 'cslip',
    nltypes.ARPHRD_SLIP6: 'slip6',
    nltypes.ARPHRD_CSLIP6: 'cslip6',
    nltypes.ARPHRD_RSRVD: 'rsrvd',
    nltypes.ARPHRD_ADAPT: 'adapt',
    nltypes.ARPHRD_ROSE: 'rose',
    nltypes.ARPHRD_X25: 'x25',
    nltypes.ARPHRD_HWX25: 'hwx25',
    nltypes.ARPHRD_CAN: 'can',
    nltypes.ARPHRD_PPP: 'ppp',
    nltypes.ARPHRD_HDLC: 'hdlc',
    nltypes.ARPHRD_LAPB: 'lapb',
    nltypes.ARPHRD_DDCMP: 'ddcmp',
    nltypes.ARPHRD_RAWHDLC: 'rawhdlc',
    nltypes.ARPHRD_TUNNEL: 'ipip',
    nltypes.ARPHRD_TUNNEL6: 'tunnel6',
    nltypes.ARPHRD_FRAD: 'frad',
    nltypes.ARPHRD_SKIP: 'skip',
    nltypes.ARPHRD_LOOPBACK: 'loopback',
    nltypes.ARPHRD_LOCALTLK: 'ltalk',
    nltypes.ARPHRD_FDDI: 'fddi',
    nltypes.ARPHRD_BIF: 'bif',
    nltypes.ARPHRD_SIT: 'sit',
    nltypes.ARPHRD_IPDDP: 'ip/ddp',
    nltypes.ARPHRD_IPGRE: 'gre',
    nltypes.ARPHRD_PIMREG: 'pimreg',
    nltypes.ARPHRD_HIPPI: 'hippi',
    nltypes.ARPHRD_ASH: 'ash',
    nltypes.ARPHRD_ECONET: 'econet',
    nltypes.ARPHRD_IRDA: 'irda',
    nltypes.ARPHRD_FCPP: 'fcpp',
    nltypes.ARPHRD_FCAL: 'fcal',
    nltypes.ARPHRD_FCPL: 'fcpl',
    nltypes.ARPHRD_FCFABRIC: 'fcfb0',
    nltypes.ARPHRD_FCFABRIC + 1: 'fcfb1',
    nltypes.ARPHRD_FCFABRIC + 2: 'fcfb2',
    nltypes.ARPHRD_FCFABRIC + 3: 'fcfb3',
    nltypes.ARPHRD_FCFABRIC + 4: 'fcfb4',
    nltypes.ARPHRD_FCFABRIC + 5: 'fcfb5',
    nltypes.ARPHRD_FCFABRIC + 6: 'fcfb6',
    nltypes.ARPHRD_FCFABRIC + 7: 'fcfb7',
    nltypes.ARPHRD_FCFABRIC + 8: 'fcfb8',
    nltypes.ARPHRD_FCFABRIC + 9: 'fcfb9',
    nltypes.ARPHRD_FCFABRIC + 10: 'fcfb10',
    nltypes.ARPHRD_FCFABRIC + 11: 'fcfb11',
    nltypes.ARPHRD_FCFABRIC + 12: 'fcfb12',
    nltypes.ARPHRD_IEEE802_TR: 'tr',
    nltypes.ARPHRD_IEEE80211: 'ieee802.11',
    nltypes.ARPHRD_IEEE80211_PRISM: 'ieee802.11/prism',
    nltypes.ARPHRD_IEEE80211_RADIOTAP: 'ieee802.11/radiotap',
    nltypes.ARPHRD_IEEE802154: ' ieee802.15.4',
    nltypes.ARPHRD_IEEE802154_MONITOR: ' ieee802.15.4/monitor',
    nltypes.ARPHRD_PHONET: ' phonet',
    nltypes.ARPHRD_PHONET_PIPE: ' phonet_pipe',
    nltypes.ARPHRD_CAIF: ' caif',
    nltypes.ARPHRD_IP6GRE: ' gre6',
    nltypes.ARPHRD_NETLINK: ' netlink',
    nltypes.ARPHRD_6LOWPAN: ' 6lowpan',
    nltypes.ARPHRD_NONE: ' none',
    nltypes.ARPHRD_VOID: 'void',
}


def iter_elements_linktype(link_type):
    try:
        yield ('link_type', link_types[link_type])
    except KeyError:
        yield ('link_type', '[{!s}]'.format(link_type))
    return None


link_events = {
    nltypes.IFLA_EVENT_NONE: 'NONE',
    nltypes.IFLA_EVENT_REBOOT: 'REBOOT',
    nltypes.IFLA_EVENT_FEATURES: 'FEATURE CHANGE',
    nltypes.IFLA_EVENT_BONDING_FAILOVER: 'BONDING FAILOVER',
    nltypes.IFLA_EVENT_NOTIFY_PEERS: 'NOTIFY PEERS',
    nltypes.IFLA_EVENT_IGMP_RESEND: 'RESEND IGMP',
    nltypes.IFLA_EVENT_BONDING_OPTIONS: 'BONDING OPTION',
}


def iter_elements_linkevent(event):
    try:
        yield ('event', link_events[event])
    except KeyError:
        yield ('event', event)
    return None


oper_states = [
    'UNKNOWN', 'NOTPRESENT', 'DOWN', 'LOWERLAYERDOWN', 'TESTING', 'DORMANT',
    'UP'
]


def iter_elements_operstate(state):
    try:
        yield ('operstate', oper_states[state])
    except IndexError:
        yield ('operstate_index', state)
    return None


def iter_linkflags(flags):
    if flags & nltypes.IFF_UP and not flags & nltypes.IFF_RUNNING:
        yield 'NO-CARRIER'
    if nltypes.IFF_LOOPBACK & flags:
        yield 'LOOPBACK'
    if nltypes.IFF_BROADCAST & flags:
        yield 'BROADCAST'
    if nltypes.IFF_POINTOPOINT & flags:
        yield 'POINTOPOINT'
    if nltypes.IFF_MULTICAST & flags:
        yield 'MULTICAST'
    if nltypes.IFF_NOARP & flags:
        yield 'NOARP'
    if nltypes.IFF_ALLMULTI & flags:
        yield 'ALLMULTI'
    if nltypes.IFF_PROMISC & flags:
        yield 'PROMISC'
    if nltypes.IFF_SLAVE & flags:
        yield 'SLAVE'
    if nltypes.IFF_DEBUG & flags:
        yield 'DEBUG'
    if nltypes.IFF_DYNAMIC & flags:
        yield 'DYNAMIC'
    if nltypes.IFF_AUTOMEDIA & flags:
        yield 'AUTOMEDIA'
    if nltypes.IFF_PORTSEL & flags:
        yield 'PORTSEL'
    if nltypes.IFF_NOTRAILERS & flags:
        yield 'NOTRAILERS'
    if nltypes.IFF_UP & flags:
        yield 'UP'
    if nltypes.IFF_LOWER_UP & flags:
        yield 'LOWER_UP'
    if nltypes.IFF_DORMANT & flags:
        yield 'DORMANT'
    if nltypes.IFF_ECHO & flags:
        yield 'ECHO'
    flags &= ~(nltypes.IFF_RUNNING | nltypes.IFF_LOOPBACK
               | nltypes.IFF_BROADCAST | nltypes.IFF_POINTOPOINT
               | nltypes.IFF_MULTICAST | nltypes.IFF_NOARP
               | nltypes.IFF_ALLMULTI | nltypes.IFF_PROMISC
               | nltypes.IFF_MASTER | nltypes.IFF_SLAVE | nltypes.IFF_DEBUG
               | nltypes.IFF_DYNAMIC
               | nltypes.IFF_AUTOMEDIA | nltypes.IFF_PORTSEL
               | nltypes.IFF_NOTRAILERS | nltypes.IFF_UP
               | nltypes.IFF_LOWER_UP | nltypes.IFF_DORMANT | nltypes.IFF_ECHO)
    if flags:
        yield '{:x}'.format(flags)
    return None


def iter_elements_by_ifinfomsg_brief(ifi, tb):
    if nltypes.IFLA_IFNAME in tb:
        yield ('ifname', ctypes.string_at(tb[nltypes.IFLA_IFNAME]).decode())
    else:
        logger.error('BUG: device with ifindex %s has nil ifname',
                     ifi.ifi_index)
        yield ('ifname', 'if{.ifi_index!s}'.format(ifi))
    if nltypes.IFLA_OPERSTATE in tb:
        yield from iter_elements_operstate(
            ctypes.c_uint8.from_buffer_copy(tb[nltypes.IFLA_OPERSTATE]).value)
    return None


def _ifi_ntoa(ifi_type, bytes_addr):
    if (4 == len(bytes_addr)
            and ifi_type in (nltypes.ARPHRD_TUNNEL, nltypes.ARPHRD_SIT,
                             nltypes.ARPHRD_IPGRE)):
        return socket.inet_ntop(socket.AF_INET, bytes_addr)
    elif (16 == len(bytes_addr)
          and ifi_type in (nltypes.ARPHRD_TUNNEL6, nltypes.ARPHRD_IP6GRE)):
        return socket.inet_ntop(socket.AF_INET6, bytes_addr)
    return ':'.join(map('{:02x}'.format, bytes_addr))


def iter_elements_by_ifinfomsg(ifi, tb, brief=False):
    if brief:
        yield from iter_elements_by_ifinfomsg_brief(ifi, tb)
        return None
    yield ('ifindex', ifi.ifi_index)
    if nltypes.IFLA_IFNAME in tb:
        yield ('ifname', ctypes.string_at(tb[nltypes.IFLA_IFNAME]).decode())
    else:
        logger.error('BUG: device with ifindex %s has nil ifname',
                     ifi.ifi_index)
        yield ('ifname', 'if{.ifi_index!s}'.format(ifi))
    yield ('flags', list(iter_linkflags(ifi.ifi_flags)))
    if nltypes.IFLA_MTU in tb:
        yield ('mtu',
               ctypes.c_uint32.from_buffer_copy(tb[nltypes.IFLA_MTU]).value)
    if nltypes.IFLA_QDISC in tb:
        yield ('qdisc', ctypes.string_at(tb[nltypes.IFLA_QDISC]).decode())
    if nltypes.IFLA_MASTER in tb:
        yield ('master',
               ctypes.c_uint32.from_buffer_copy(tb[nltypes.IFLA_MASTER]).value)
    if nltypes.IFLA_OPERSTATE in tb:
        yield from iter_elements_operstate(
            ctypes.c_uint8.from_buffer_copy(tb[nltypes.IFLA_OPERSTATE]).value)
    if nltypes.IFLA_GROUP in tb:
        yield ('group',
               ctypes.c_uint32.from_buffer_copy(tb[nltypes.IFLA_GROUP]).value)
    if (nltypes.IFLA_TXQLEN in tb and ctypes.c_uint32.from_buffer_copy(
            tb[nltypes.IFLA_TXQLEN]).value):
        yield ('txqlen',
               ctypes.c_uint32.from_buffer_copy(tb[nltypes.IFLA_TXQLEN]).value)
    if nltypes.IFLA_EVENT in tb:
        yield from iter_ekements_linkevent(
            ctypes.c_uint32.from_buffer_copy(tb[nltypes.IFLA_EVENT]).value)
    yield from iter_elements_linktype(ifi.ifi_type)
    if nltypes.IFLA_ADDRESS in tb:
        yield ('address', _ifi_ntoa(ifi.ifi_type, tb[nltypes.IFLA_ADDRESS]))
    if nltypes.IFLA_BROADCAST in tb:
        if nltypes.IFF_POINTOPOINT & ifi.ifi_flags:
            yield ('link_pointtopoint', True)
        yield ('broadcast', _ifi_ntoa(ifi.ifi_type,
                                      tb[nltypes.IFLA_BROADCAST]))
    return None


ifa_flag_names = {
    nltypes.IFA_F_SECONDARY: 'secondary',
    nltypes.IFA_F_NODAD: 'nodad',
    nltypes.IFA_F_OPTIMISTIC: 'optimistic',
    nltypes.IFA_F_DADFAILED: 'dadfailed',
    nltypes.IFA_F_HOMEADDRESS: 'home',
    nltypes.IFA_F_DEPRECATED: 'deprecated',
    nltypes.IFA_F_TENTATIVE: 'tentative',
    nltypes.IFA_F_PERMANENT: 'permanent',
    nltypes.IFA_F_MANAGETEMPADDR: 'mngtmpaddr',
    nltypes.IFA_F_NOPREFIXROUTE: 'noprefixroute',
    nltypes.IFA_F_MCAUTOJOIN: 'autojoin',
    nltypes.IFA_F_STABLE_PRIVACY: 'stable-privacy',
}


def iter_elements_by_ifa_falgs(ifa, flags):
    for mask, name in ifa_flag_names.items():
        if mask == nltypes.IFA_F_PERMANENT:
            if not flags & mask:
                yield ('dynamic', True)
        elif flags & mask:
            if (mask == nltypes.IFA_F_SECONDARY
                    and ifa.ifa_family == socket.AF_INET6):
                yield ('temporary', True)
            else:
                yield (name, True)
        flags &= ~mask
    if flags:
        yield (ifa_flags, '{:02x}'.format(flags))
    return None


rtscope_names = {
    nltypes.RT_SCOPE_UNIVERSE: 'global',
    nltypes.RT_SCOPE_NOWHERE: 'nowhere',
    nltypes.RT_SCOPE_HOST: 'host',
    nltypes.RT_SCOPE_LINK: 'link',
    nltypes.RT_SCOPE_SITE: 'site',
}

family_names = {
    socket.AF_INET: 'inet',
    socket.AF_INET6: 'inet6',
    socket.AF_PACKET: 'link',
    socket.AF_IPX: 'ipx',
    0x1c: 'mpls',  # AF_MPLS
    socket.AF_BRIDGE: 'bridge',
}


def iter_elements_by_ifaddrmsg(ifa, tb, brief=False):
    if not brief:
        if ifa.ifa_family in family_names:
            yield ('family', family_names.get(ifa.ifa_family, '???'))
        else:
            yield ('family_index', ifa.ifa_family)
    if nltypes.IFA_LOCAL in tb:
        local = tb[nltypes.IFA_LOCAL]
    elif nltypes.IFA_ADDRESS in tb:
        local = tb[nltypes.IFA_ADDRESS]
    else:
        local = None
    if local:
        yield ('local', socket.inet_ntop(ifa.ifa_family, local))
        if (nltypes.IFA_ADDRESS in tb and tb[nltypes.IFA_ADDRESS] is not local
                and any(a != l
                        for a, l in zip(tb[nltypes.IFA_ADDRESS], local))):
            yield ('address',
                   socket.inet_ntop(ifa.ifa_family, tb[nltypes.IFA_ADDRESS]))
        yield ('prefixlen', ifa.ifa_prefixlen)
        if nltypes.IFA_RT_PRIORITY in tb:
            yield ('metric',
                   ctypes.c_uint32.from_buffer_copy(
                       tb[nltypes.IFA_RT_PRIORITY]).value)
    if brief:
        return None
    if nltypes.IFA_BROADCAST in tb:
        yield ('broadcast',
               socket.inet_ntop(ifa.ifa_family, tb[nltypes.IFA_BROADCAST]))
    if nltypes.IFA_ANYCAST in tb:
        yield ('anycast',
               socket.inet_ntop(ifa.ifa_family, tb[nltypes.IFA_ANYCAST]))
    if ifa.ifa_scope in rtscope_names:
        yield ('scope', rtscope_names[ifa.ifa_scope])
    else:
        yield ('scope', ifa.ifa_scop)
    if nltypes.IFA_FLAGS in tb:
        yield from iter_elements_by_ifa_falgs(
            ifa,
            ctypes.c_uint32.from_buffer_copy(tb[nltypes.IFA_FLAGS]).value)
    else:
        yield from iter_elements_by_ifa_falgs(ifa, ifa.ifa_flags)
    if nltypes.IFA_LABEL in tb:
        yield ('label', ctypes.string_at(tb[nltypes.IFA_LABEL]).decode())
    if nltypes.IFA_CACHEINFO in tb:
        ci = nltypes.c_ifa_cacheinfo.from_buffer_copy(
            tb[nltypes.IFA_CACHEINFO])
        yield ('valid_life_time', ci.ifa_valid)
        yield ('preferred_life_time', ci.ifa_prefered)
    return None


def iter_addrinfo(addr_list, brief=False):
    yield from (dict(iter_elements_by_ifaddrmsg(ifa, ifa_attr, brief=brief)) for ifa, ifa_attr in addr_list)
    return None


def iter_linkinfo(link_list,
                  addr_list,
                  brief=False):
    addr_tab = dict()
    for _ in addr_list:
        ifa, ifa_attr = _
        addr_tab.setdefault(ifa.ifa_index, []).append(_)
    for ifi, ifi_attr in link_list:
        linkinfo = dict(iter_elements_by_ifinfomsg(ifi, ifi_attr, brief=brief))
        addr_list = addr_tab.pop(ifi.ifi_index, None)
        if addr_list:
            linkinfo['addr_info'] = list(iter_addrinfo(addr_list, brief=brief))
        yield linkinfo
    return None
