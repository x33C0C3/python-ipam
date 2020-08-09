__all__ = (
    'nl_strerror',
    'nl_open',
    'Handle',
)

import enum
import ctypes
import socket
import logging
import asyncio

from . import (remove_l, add_l, filter_iter_link, filter_iter_addr, rtnl_addr, rtnl_link)
from . import nltypes

logger = logging.getLogger(__package__)


class nl_errno(enum.IntEnum):
    NLE_SUCCESS = 0
    NLE_FAILURE = 1
    NLE_INTR = 2
    NLE_BAD_SOCK = 3
    NLE_AGAIN = 4
    NLE_NOMEM = 5
    NLE_EXIST = 6
    NLE_INVAL = 7
    NLE_RANGE = 8
    NLE_MSGSIZE = 9
    NLE_OPNOTSUPP = 10
    NLE_AF_NOSUPPORT = 11
    NLE_OBJ_NOTFOUND = 12
    NLE_NOATTR = 13
    NLE_MISSING_ATTR = 14
    NLE_AF_MISMATCH = 15
    NLE_SEQ_MISMATCH = 16
    NLE_MSG_OVERFLOW = 17
    NLE_MSG_TRUNC = 18
    NLE_NOADDR = 19
    NLE_SRCRT_NOSUPPORT = 20
    NLE_MSG_TOOSHORT = 21
    NLE_MSGTYPE_NOSUPPORT = 22
    NLE_OBJ_MISMATCH = 23
    NLE_NOCACHE = 24
    NLE_BUSY = 25
    NLE_PROTO_MISMATCH = 26
    NLE_NOACCESS = 27
    NLE_PERM = 28
    NLE_PKTLOC_FILE = 29
    NLE_PARSE_ERR = 30
    NLE_NODEV = 31
    NLE_IMMUTABLE = 32
    NLE_DUMP_INTR = 33
    NLE_ATTRSIZE = 34


nl_errmsg = {
    nl_errno.NLE_SUCCESS: 'Success',
    nl_errno.NLE_FAILURE: 'Unspecific failure',
    nl_errno.NLE_INTR: 'Interrupted system call',
    nl_errno.NLE_BAD_SOCK: 'Bad socket',
    nl_errno.NLE_AGAIN: 'Try again',
    nl_errno.NLE_NOMEM: 'Out of memory',
    nl_errno.NLE_EXIST: 'Object exists',
    nl_errno.NLE_INVAL: 'Invalid input data or parameter',
    nl_errno.NLE_RANGE: 'Input data out of range',
    nl_errno.NLE_MSGSIZE: 'Message size not sufficient',
    nl_errno.NLE_OPNOTSUPP: 'Operation not supported',
    nl_errno.NLE_AF_NOSUPPORT: 'Address family not supported',
    nl_errno.NLE_OBJ_NOTFOUND: 'Object not found',
    nl_errno.NLE_NOATTR: 'Attribute not available',
    nl_errno.NLE_MISSING_ATTR: 'Missing attribute',
    nl_errno.NLE_AF_MISMATCH: 'Address family mismatch',
    nl_errno.NLE_SEQ_MISMATCH: 'Message sequence number mismatch',
    nl_errno.NLE_MSG_OVERFLOW: 'Kernel reported message overflow',
    nl_errno.NLE_MSG_TRUNC: 'Kernel reported truncated message',
    nl_errno.NLE_NOADDR: 'Invalid address for specified address family',
    nl_errno.NLE_SRCRT_NOSUPPORT: 'Source based routing not supported',
    nl_errno.NLE_MSG_TOOSHORT: 'Netlink message is too short',
    nl_errno.NLE_MSGTYPE_NOSUPPORT: 'Netlink message type is not supported',
    nl_errno.NLE_OBJ_MISMATCH: 'Object type does not match cache',
    nl_errno.NLE_NOCACHE: 'Unknown or invalid cache type',
    nl_errno.NLE_BUSY: 'Object busy',
    nl_errno.NLE_PROTO_MISMATCH: 'Protocol mismatch',
    nl_errno.NLE_NOACCESS: 'No Access',
    nl_errno.NLE_PERM: 'Operation not permitted',
    nl_errno.NLE_PKTLOC_FILE: 'Unable to open packet location file',
    nl_errno.NLE_PARSE_ERR: 'Unable to parse object',
    nl_errno.NLE_NODEV: 'No such device',
    nl_errno.NLE_IMMUTABLE: 'Immutable attribute',
    nl_errno.NLE_DUMP_INTR: 'Dump inconsistency detected, interrupted',
    nl_errno.NLE_ATTRSIZE: 'Attribute max length exceeded',
}


def nl_dump_error(nlh):
    return -NLMSG_DATA(nlh, c_nlmsgerr).error


def nl_strerror(errno):
    return nl_errmsg.get(errno)


def nl_open(sub=None, proto=None):
    if None is proto:
        proto = socket.NETLINK_ROUTE
    if None is sub:
        sub = 0
    sock = socket.socket(socket.AF_NETLINK,
                         socket.SOCK_RAW | socket.SOCK_CLOEXEC, proto)
    sock.bind((socket.AF_NETLINK, sub))
    return sock


def rtnl_linkdump_req(seq, family=None):
    if None is family:
        family = socket.AF_PACKET
    buf = (ctypes.c_ubyte * nltypes.NLMSG_SPACE(
        ctypes.sizeof(nltypes.c_ifinfomsg)))()
    nlh = nltypes.c_nlmsghdr.from_buffer(buf)
    nlh.nlmsg_len = nltypes.NLMSG_LENGTH(ctypes.sizeof(nltypes.c_ifinfomsg))
    nlh.nlmsg_type = nltypes.RTM_GETLINK
    nlh.nlmsg_flags = nltypes.NLM_F_DUMP | nltypes.NLM_F_REQUEST
    nlh.nlmsg_seq = seq
    ifm = nltypes.NLMSG_DATA(nlh, nltypes.c_ifinfomsg)
    ifm.ifa_family = family
    return bytes(buf)


def rtnl_addrdump_req(seq, family=None):
    if None is family:
        family = socket.AF_PACKET
    buf = (ctypes.c_ubyte * nltypes.NLMSG_SPACE(
        ctypes.sizeof(nltypes.c_ifaddrmsg)))()
    nlh = nltypes.c_nlmsghdr.from_buffer(buf)
    nlh.nlmsg_len = nltypes.NLMSG_LENGTH(ctypes.sizeof(nltypes.c_ifaddrmsg))
    nlh.nlmsg_type = nltypes.RTM_GETADDR
    nlh.nlmsg_flags = nltypes.NLM_F_DUMP | nltypes.NLM_F_REQUEST
    nlh.nlmsg_seq = seq
    ifm = nltypes.NLMSG_DATA(nlh, nltypes.c_ifaddrmsg)
    ifm.ifa_family = family
    return bytes(buf)


async def nl_recv_and_put_in_queue(sock, queue, *, loop=None):
    if None is loop:
        loop = asyncio.get_event_loop()
    buf = (ctypes.c_ubyte * 4096)()
    n = 0
    while True:
        if 0 < n:
            logger.error('%r.recv with 0 < n: n = %d', sock, n)
        n = await loop.sock_recv_into(sock, buf)
        nlh = nltypes.c_nlmsghdr.from_buffer(buf)
        while nltypes.NLMSG_OK(nlh, n):
            msg = bytes((ctypes.c_ubyte * nlh.nlmsg_len).from_address(
                ctypes.addressof(nlh)))
            #logger.debug(
            #    '<queue at 0x%x qsize=%d>.put(<object at 0x%x>)',
            #    id(queue), queue.qsize(), id(msg))
            await queue.put(msg)
            #logger.debug(
            #    '<queue at 0x%x qsize=%d>.put(<object at 0x%x>) completed',
            #    id(queue), queue.qsize(), id(msg))
            await asyncio.sleep(0, loop=loop)
            nlh, n = nltypes.NLMSG_NEXT(nlh, n)
    return None


class Handle(object):
    async def _get_nlmsg(self):
        #logger.debug(
        #      '<queue at 0x%x qsize=%d>.get()',
        #      id(self._queue), self._queue.qsize())
        msg = await self._queue.get()
        #logger.debug(
        #    '<queue at 0x%x qsize=%d>.get() answer <object at 0x%x>',
        #    id(self._queue), self._queue.qsize(), id(msg))
        buf = (ctypes.c_ubyte * len(msg)).from_buffer_copy(msg)
        return nltypes.c_nlmsghdr.from_buffer(buf)

    async def _update(self, state=0):
        msg = await self._get_nlmsg()
        nlmsg_pid = msg.nlmsg_pid
        nlmsg_seq = msg.nlmsg_seq
        if state in (4,
                     2) and nlmsg_pid == self._pid and nlmsg_seq == self._seq:
            state -= 1
        while True:
            logger.debug('%r', msg)
            if nltypes.NLMSG_NOOP == msg.nlmsg_type:
                pass
            if nltypes.NLMSG_DONE == msg.nlmsg_type:
                break
            elif 0 is state:
                if nltypes.RTM_NEWLINK == msg.nlmsg_type:
                    add_l(self._link_list, rtnl_link(msg))
                elif nltypes.RTM_DELLINK == msg.nlmsg_type:
                    remove_l(self._link_list, rtnl_link(msg))
                elif nltypes.RTM_NEWADDR == msg.nlmsg_type:
                    add_l(self._addr_list, rtnl_addr(msg))
                elif nltypes.RTM_DELADDR == msg.nlmsg_type:
                    remove_l(self._addr_list, rtnl_addr(msg))
            elif 1 == state:
                if nltypes.NLMSG_ERROR == msg.nlmsg_type:
                    errno = nl_dump_error(msg)
                    logger.error('NETLINK: %s (%d)', nl_strerror(errno), errno)
                elif nltypes.RTM_NEWADDR == msg.nlmsg_type:
                    add_l(self._addr_list, rtnl_addr(msg))
                else:
                    logger.error(
                        'Unknown message: len=0x%08x type=0x%04x flag=0x%04x',
                        msg.nlmsg_len, msg.nlmsg_type, msg.nlmsg_flags)
            elif 2 == state:
                if nltypes.RTM_NEWLINK == msg.nlmsg_type:
                    add_l(self._link_list, rtnl_link(msg))
                elif nltypes.RTM_DELLINK == msg.nlmsg_type:
                    remove_l(self._link_list, rtnl_link(msg))
            elif 3 == state:
                if nltypes.NLMSG_ERROR == msg.nlmsg_type:
                    errno = nl_dump_error(msg)
                    logger.error('NETLINK: %s (%d)', nl_strerror(errno), errno)
                elif nltypes.RTM_NEWLINK == msg.nlmsg_type:
                    add_l(self._link_list, rtnl_link(msg))
                else:
                    logger.error(
                        'Unknown message: len=0x%08x type=0x%04x flag=0x%04x',
                        msg.nlmsg_len, msg.nlmsg_type, msg.nlmsg_flags)
            elif 4 == state:
                pass
            else:
                raise ValueError
            if nltypes.NLM_F_MULTI & ~msg.nlmsg_flags:
                break
            while True:
                try:
                    msg = await self._get_nlmsg()
                except asyncio.CancelledError:
                    pass
                else:
                    break
        return state

    async def update(self, pray=None):
        async with self._lock:
            if not self._sub:
                if None is pray:
                    pray = True
                elif not pray:
                    raise ValueError
            if None is self._seq:
                pray = True
            if pray:
                state = 5
                self.clear()
                self._seq = int(self._loop.time())
                try:
                    while 1 < state:
                        if 5 == state:
                            self._seq += 1
                            await self._loop.sock_sendall(
                                self._sock, rtnl_linkdump_req(self._seq))
                            state -= 1
                        elif 3 == state:
                            self._seq += 1
                            await self._loop.sock_sendall(
                                self._sock, rtnl_addrdump_req(self._seq))
                            state -= 1
                        state = await self._update(state)
                except asyncio.CancelledError:
                    self._seq = None
            else:
                await self._update()
        return None

    def clear(self):
        self._seq = None
        self._link_list.clear()
        self._addr_list.clear()
        return None

    def items(self,
            index=None,
            ifname=None,
            family=None):
        index = set(ifi.ifi_index for ifi, _ in filter_iter_link(self._link_list, index=index, ifname=ifname))
        links = filter_iter_link(self._link_list, index=index)
        addrs = filter_iter_addr(self._addr_list, index=index, family=family)
        return (links, addrs)

    async def close(self):
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        return None

    def __init__(self, sub=None, proto=None, *, sock=None, loop=None):
        if None is loop:
            loop = asyncio.get_event_loop()
        if None is sock:
            sock = nl_open(sub=sub, proto=proto)
            sock.setblocking(False)
        elif None is not sub or None is not proto:
            raise ValueError
        elif sock.getblocking():
            raise ValueError
        object.__init__(self)
        self._loop = loop
        self._sock = sock
        self._pid, self._sub = self._sock.getsockname()
        self._queue = asyncio.Queue(maxsize=1, loop=self._loop)
        self._task = self._loop.create_task(
            nl_recv_and_put_in_queue(self._sock, self._queue, loop=self._loop))
        self._lock = asyncio.Lock(loop=self._loop)
        self._seq = None
        self._link_list = list()
        self._addr_list = list()
        return None
