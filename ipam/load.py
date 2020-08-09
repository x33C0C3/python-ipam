import sys
import ctypes
import logging
import json
import argparse

from . import add_l, remove_l, rtnl_addr, rtnl_link
from . import nltypes
from . import utils
from . import prints

logger = logging.getLogger(__package__)


def iter_nlmsg_in_fileobj(fileobj):
    if not isinstance(fileobj.read(0), bytes):
        raise TypeError
    n = 0
    buf = (ctypes.c_ubyte * 4096)()
    while True:
        if 0 < n:
            ctypes.memmove(buf,
                           ctypes.addressof(buf) + (ctypes.sizeof(buf) - n), n)
        data = fileobj.read(ctypes.sizeof(buf) - n)
        if not data:
            if 0 < n:
                raise ValueError
            return None
        buf[n:n + len(data)] = data
        n += len(data)
        msg = nltypes.c_nlmsghdr.from_buffer(buf)
        while nltypes.NLMSG_OK(msg, n):
            yield msg
            msg, n = nltypes.NLMSG_NEXT(msg, n)
    return None


def main(args=None, namespace=None, *, outfile=None):
    if None is outfile:
        outfile = sys.stdout
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--brief', action='store_true')
    parser.add_argument('-j', '--json', action='store_true')
    parser.add_argument('-f', '--file', type=argparse.FileType('rb'))
    parser.add_argument('-i', '--interface', action='append')
    namespace = parser.parse_args(args=args, namespace=namespace)
    if None is namespace.file or sys.stdin is namespace.file:
        namespace.file = sys.stdin.buffer
    link_list = list()
    addr_list = list()
    for msg in iter_nlmsg_in_fileobj(namespace.file):
        if nltypes.RTM_NEWLINK == msg.nlmsg_type:
            x = rtnl_link(msg)
            add_l(link_list, x)
            logger.debug('new: %r', x)
        elif nltypes.RTM_DELLINK == msg.nlmsg_type:
            x = rtnl_link(msg)
            remove_l(link_list, x)
            logger.debug('del: %r', x)
        elif nltypes.RTM_NEWADDR == msg.nlmsg_type:
            x = rtnl_addr(msg)
            add_l(addr_list, x)
            logger.debug('new: %r', x)
        elif nltypes.RTM_DELADDR == msg.nlmsg_type:
            x = rtnl_addr(msg)
            remove_l(addr_list, x)
            logger.debug('del: %r', x)
        else:
            logger.info('Unknown message: len=0x%08x type=0x%04x flag=0x%04x',
                        msg.nlmsg_len, msg.nlmsg_type, msg.nlmsg_flags)
    linkinfos = utils.iter_linkinfo(
        link_list,
        addr_list,
        brief=namespace.brief,
        ifname_set=namespace.interface)
    if namespace.json:
        json.dump(list(linkinfos), outfile, indent=4)
        if outfile.isatty():
            outfile.write('\n')
    else:
        for chunk in prints.iterencode(linkinfos, brief=namespace.brief):
            outfile.write(chunk)
        if outfile.isatty():
            outfile.write('\n')
    return None


if __name__ == '__main__':
    main()
