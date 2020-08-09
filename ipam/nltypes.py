import enum
import ctypes


class _Structure(ctypes.Structure):
    def __repr__(self):
        itr = map('{0[0]!s}={0[1]!r}'.format,
                  ((name, getattr(self, name)) for name, _ in self._fields_))
        return '{.__class__.__name__}({!s})'.format(self, ', '.join(itr))


ctypes.Structure = _Structure

# linux/netlink.h


class c_nlmsghdr(ctypes.Structure):
    _fields_ = (
        ('nlmsg_len', ctypes.c_uint32),
        ('nlmsg_type', ctypes.c_uint16),
        ('nlmsg_flags', ctypes.c_uint16),
        ('nlmsg_seq', ctypes.c_uint32),
        ('nlmsg_pid', ctypes.c_uint32),
    )


NLM_F_REQUEST = 0x01
NLM_F_MULTI = 0x02
NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH

NLMSG_ALIGNTO = 4


def NLMSG_ALIGN(len):
    return (len + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1)


NLMSG_HDRLEN = NLMSG_ALIGN(ctypes.sizeof(c_nlmsghdr))


def NLMSG_LENGTH(len):
    return len + NLMSG_HDRLEN


def NLMSG_SPACE(len):
    return NLMSG_ALIGN(NLMSG_LENGTH(len))


def NLMSG_DATA(nlh, cls):
    return cls.from_address(ctypes.addressof(nlh) + NLMSG_LENGTH(0))


def NLMSG_NEXT(nlh, len):
    len -= NLMSG_ALIGN(nlh.nlmsg_len)
    nlh = c_nlmsghdr.from_address(
        ctypes.addressof(nlh) + NLMSG_ALIGN(nlh.nlmsg_len))
    return nlh, len


def NLMSG_OK(nlh, len):
    return (len >= ctypes.sizeof(c_nlmsghdr)
            and nlh.nlmsg_len >= ctypes.sizeof(c_nlmsghdr)
            and nlh.nlmsg_len <= len)


def NLMSG_PAYLOAD(nlh, len):
    return nlh.nlmsg_len - NLMSG_SPACE(len)


NLMSG_NOOP = 0x1
NLMSG_ERROR = 0x2
NLMSG_DONE = 0x3
NLMSG_OVERRUN = 0x4


class c_nlmsgerr(ctypes.Structure):
    _fields_ = (
        ('error', ctypes.c_int),
        ('msg', c_nlmsghdr),
    )


# linux/if.h


class net_device_flags(enum.IntFlag):
    IFF_UP = 1 << 0
    IFF_BROADCAST = 1 << 1
    IFF_DEBUG = 1 << 2
    IFF_LOOPBACK = 1 << 3
    IFF_POINTOPOINT = 1 << 4
    IFF_NOTRAILERS = 1 << 5
    IFF_RUNNING = 1 << 6
    IFF_NOARP = 1 << 7
    IFF_PROMISC = 1 << 8
    IFF_ALLMULTI = 1 << 9
    IFF_MASTER = 1 << 10
    IFF_SLAVE = 1 << 11
    IFF_MULTICAST = 1 << 12
    IFF_PORTSEL = 1 << 13
    IFF_AUTOMEDIA = 1 << 14
    IFF_DYNAMIC = 1 << 15
    IFF_LOWER_UP = 1 << 16
    IFF_DORMANT = 1 << 17
    IFF_ECHO = 1 << 18


globals().update(net_device_flags.__members__)

# linux/if_link.h


class ifi_rta_types(enum.IntEnum):
    IFLA_UNSPEC = 0
    IFLA_ADDRESS = 1
    IFLA_BROADCAST = 2
    IFLA_IFNAME = 3
    IFLA_MTU = 4
    IFLA_LINK = 5
    IFLA_QDISC = 6
    IFLA_STATS = 7
    IFLA_COST = 8
    IFLA_PRIORITY = 9
    IFLA_MASTER = 10
    IFLA_WIRELESS = 11
    IFLA_PROTINFO = 12
    IFLA_TXQLEN = 13
    IFLA_MAP = 14
    IFLA_WEIGHT = 15
    IFLA_OPERSTATE = 16
    IFLA_LINKMODE = 17
    IFLA_LINKINFO = 18
    IFLA_NET_NS_PID = 19
    IFLA_IFALIAS = 20
    IFLA_NUM_VF = 21
    IFLA_VFINFO_LIST = 22
    IFLA_STATS64 = 23
    IFLA_VF_PORTS = 24
    IFLA_PORT_SELF = 25
    IFLA_AF_SPEC = 26
    IFLA_GROUP = 27
    IFLA_NET_NS_FD = 28
    IFLA_EXT_MASK = 29
    IFLA_PROMISCUITY = 30
    IFLA_NUM_TX_QUEUES = 31
    IFLA_NUM_RX_QUEUES = 32
    IFLA_CARRIER = 33
    IFLA_PHYS_PORT_ID = 34
    IFLA_CARRIER_CHANGES = 35
    IFLA_PHYS_SWITCH_ID = 36
    IFLA_LINK_NETNSID = 37
    IFLA_PHYS_PORT_NAME = 38
    IFLA_PROTO_DOWN = 39
    IFLA_GSO_MAX_SEGS = 40
    IFLA_GSO_MAX_SIZE = 41
    IFLA_PAD = 42
    IFLA_XDP = 43
    IFLA_EVENT = 44
    IFLA_NEW_NETNSID = 45
    IFLA_IF_NETNSID = 46
    IFLA_CARRIER_UP_COUNT = 47
    IFLA_CARRIER_DOWN_COUNT = 48
    IFLA_NEW_IFINDEX = 49
    IFLA_MIN_MTU = 50
    IFLA_MAX_MTU = 51


globals().update(ifi_rta_types.__members__)

IFLA_MAX = max(ifi_rta_types)


def IFLA_RTA(r):
    IFLALEN = NLMSG_ALIGN(ctypes.sizeof(c_ifinfomsg))
    return c_rtattr.from_address(ctypes.addressof(r) + IFLALEN)


def IFLA_PAYLOAD(n):
    return NLMSG_PAYLOAD(n, ctypes.sizeof(c_ifinfomsg))


class ifi_rta_events(enum.IntEnum):
    IFLA_EVENT_NONE = 0
    IFLA_EVENT_REBOOT = 1
    IFLA_EVENT_FEATURES = 2
    IFLA_EVENT_BONDING_FAILOVER = 3
    IFLA_EVENT_NOTIFY_PEERS = 4
    IFLA_EVENT_IGMP_RESEND = 5
    IFLA_EVENT_BONDING_OPTIONS = 6


globals().update(ifi_rta_events.__members__)

# linux/if_addr.h


class c_ifaddrmsg(ctypes.Structure):
    _fields_ = (
        ('ifa_family', ctypes.c_uint8),
        ('ifa_prefixlen', ctypes.c_uint8),
        ('ifa_flags', ctypes.c_uint8),
        ('ifa_scope', ctypes.c_uint8),
        ('ifa_index', ctypes.c_uint32),
    )


class ifa_rta_types(enum.IntEnum):
    IFA_UNSPEC = 0
    IFA_ADDRESS = 1
    IFA_LOCAL = 2
    IFA_LABEL = 3
    IFA_BROADCAST = 4
    IFA_ANYCAST = 5
    IFA_CACHEINFO = 6
    IFA_MULTICAST = 7
    IFA_FLAGS = 8
    IFA_RT_PRIORITY = 9


globals().update(ifa_rta_types.__members__)

IFA_MAX = max(ifa_rta_types)


class ifa_flags(enum.IntFlag):
    IFA_F_SECONDARY = 0x01
    IFA_F_TEMPORARY = IFA_F_SECONDARY
    IFA_F_NODAD = 0x02
    IFA_F_OPTIMISTIC = 0x04
    IFA_F_DADFAILED = 0x08
    IFA_F_HOMEADDRESS = 0x10
    IFA_F_DEPRECATED = 0x20
    IFA_F_TENTATIVE = 0x40
    IFA_F_PERMANENT = 0x80
    IFA_F_MANAGETEMPADDR = 0x100
    IFA_F_NOPREFIXROUTE = 0x200
    IFA_F_MCAUTOJOIN = 0x400
    IFA_F_STABLE_PRIVACY = 0x800


globals().update(ifa_flags.__members__)


class c_ifa_cacheinfo(ctypes.Structure):
    _fields_ = (
        ('ifa_prefered', ctypes.c_uint32),
        ('ifa_valid', ctypes.c_uint32),
        ('cstamp', ctypes.c_uint32),
        ('tstamp', ctypes.c_uint32),
    )


def IFA_RTA(r):
    IFALEN = NLMSG_ALIGN(ctypes.sizeof(c_ifaddrmsg))
    return c_rtattr.from_address(ctypes.addressof(r) + IFALEN)


def IFA_PAYLOAD(n):
    return NLMSG_PAYLOAD(n, ctypes.sizeof(c_ifaddrmsg))


# linux/rtnetlink.h


class nlmsg_types(enum.IntEnum):
    RTM_NEWLINK = 16
    RTM_DELLINK = 17
    RTM_GETLINK = 18
    RTM_NEWADDR = 20
    RTM_DELADDR = 21
    RTM_GETADDR = 22


globals().update(nlmsg_types.__members__)


class c_rtattr(ctypes.Structure):
    _fields_ = (
        ('rta_len', ctypes.c_ushort),
        ('rta_type', ctypes.c_ushort),
    )


RTA_ALIGNTO = 4


def RTA_ALIGN(len):
    return (len + RTA_ALIGNTO - 1) & ~(RTA_ALIGNTO - 1)


def RTA_OK(rta, len):
    return (len >= ctypes.sizeof(c_rtattr)
            and rta.rta_len >= ctypes.sizeof(c_rtattr) and rta.rta_len <= len)


def RTA_NEXT(rta, attrlen):
    attrlen -= RTA_ALIGN(rta.rta_len)
    rta = c_rtattr.from_address(ctypes.addressof(rta) + RTA_ALIGN(rta.rta_len))
    return rta, attrlen


def RTA_LENGTH(len):
    return RTA_ALIGN(ctypes.sizeof(c_rtattr)) + len


def RTA_SPACE(len):
    return RTA_ALIGN(RTA_LENGTH(len))


def RTA_DATA(rta, cls):
    return cls.from_address(ctypes.addressof(rta) + RTA_LENGTH(0))


def RTA_PAYLOAD(rta):
    return rta.rta_len - RTA_LENGTH(0)


class rt_scope_t(enum.IntEnum):
    RT_SCOPE_UNIVERSE = 0
    RT_SCOPE_SITE = 200
    RT_SCOPE_LINK = 253
    RT_SCOPE_HOST = 254
    RT_SCOPE_NOWHERE = 255


globals().update(rt_scope_t.__members__)


class c_ifinfomsg(ctypes.Structure):
    _fields_ = (
        ('ifi_family', ctypes.c_ubyte),
        ('__ifi_pad', ctypes.c_ubyte),
        ('ifi_type', ctypes.c_ushort),
        ('ifi_index', ctypes.c_int),
        ('ifi_flags', ctypes.c_uint),
        ('ifi_change', ctypes.c_uint),
    )


RTMGRP_LINK = 1
RTMGRP_IPV4_IFADDR = 0x10
RTMGRP_IPV6_IFADDR = 0x100

# linux/if_arp.h


class ARPHRD(enum.IntEnum):
    ARPHRD_NETROM = 0
    ARPHRD_ETHER = 1
    ARPHRD_EETHER = 2
    ARPHRD_AX25 = 3
    ARPHRD_PRONET = 4
    ARPHRD_CHAOS = 5
    ARPHRD_IEEE802 = 6
    ARPHRD_ARCNET = 7
    ARPHRD_APPLETLK = 8
    ARPHRD_DLCI = 15
    ARPHRD_ATM = 19
    ARPHRD_METRICOM = 23
    ARPHRD_IEEE1394 = 24
    ARPHRD_EUI64 = 27
    ARPHRD_INFINIBAND = 32
    ARPHRD_SLIP = 256
    ARPHRD_CSLIP = 257
    ARPHRD_SLIP6 = 258
    ARPHRD_CSLIP6 = 259
    ARPHRD_RSRVD = 260
    ARPHRD_ADAPT = 264
    ARPHRD_ROSE = 270
    ARPHRD_X25 = 271
    ARPHRD_HWX25 = 272
    ARPHRD_CAN = 280
    ARPHRD_PPP = 512
    ARPHRD_CISCO = 513
    ARPHRD_HDLC = ARPHRD_CISCO
    ARPHRD_LAPB = 516
    ARPHRD_DDCMP = 517
    ARPHRD_RAWHDLC = 518
    ARPHRD_RAWIP = 519
    ARPHRD_TUNNEL = 768
    ARPHRD_TUNNEL6 = 769
    ARPHRD_FRAD = 770
    ARPHRD_SKIP = 771
    ARPHRD_LOOPBACK = 772
    ARPHRD_LOCALTLK = 773
    ARPHRD_FDDI = 774
    ARPHRD_BIF = 775
    ARPHRD_SIT = 776
    ARPHRD_IPDDP = 777
    ARPHRD_IPGRE = 778
    ARPHRD_PIMREG = 779
    ARPHRD_HIPPI = 780
    ARPHRD_ASH = 781
    ARPHRD_ECONET = 782
    ARPHRD_IRDA = 783
    ARPHRD_FCPP = 784
    ARPHRD_FCAL = 785
    ARPHRD_FCPL = 786
    ARPHRD_FCFABRIC = 787
    ARPHRD_IEEE802_TR = 800
    ARPHRD_IEEE80211 = 801
    ARPHRD_IEEE80211_PRISM = 802
    ARPHRD_IEEE80211_RADIOTAP = 803
    ARPHRD_IEEE802154 = 804
    ARPHRD_IEEE802154_MONITOR = 805
    ARPHRD_PHONET = 820
    ARPHRD_PHONET_PIPE = 821
    ARPHRD_CAIF = 822
    ARPHRD_IP6GRE = 823
    ARPHRD_NETLINK = 824
    ARPHRD_6LOWPAN = 825
    ARPHRD_VSOCKMON = 826
    ARPHRD_VOID = 0xFFFF
    ARPHRD_NONE = 0xFFFE


globals().update(ARPHRD.__members__)
