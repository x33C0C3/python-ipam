import sys
import os
import functools
import asyncio
import json
import argparse

from . import nltypes
from . import utils
from . import recvs
from . import dumps
from . import prints


async def print_raw(link_list,
                    addr_list,
                    *,
                    file=sys.stdout,
                    loop=None):
    file = file.buffer
    for chunk in dumps.iterencode(link_list, addr_list):
        file.write(chunk)
    return None


async def print_json(link_list,
                     addr_list,
                     *,
                     brief=False,
                     file=sys.stdout,
                     end='',
                     loop=None):
    linkinfos = utils.iter_linkinfo(link_list, addr_list, brief=brief)
    json.dump(list(linkinfos), file, indent=4)
    if end:
        file.write(end)
    return None


async def print_tile(link_list,
                     addr_list,
                     *,
                     brief=False,
                     file=sys.stdout,
                     end='',
                     loop=None):
    linkinfos = utils.iter_linkinfo(link_list, addr_list, brief=brief)
    for chunk in prints.iterencode(linkinfos, brief=brief):
        file.write(chunk)
    if end:
        file.write(end)
    return None


_DEFAULT_PRINTER = print_tile


async def h_file(filename, link_list, addr_list, *, printer=None, loop=None):
    if None is loop:
        loop = asyncio.get_event_loop()
    if None is printer:
        printer = _DEFAULT_PRINTER
    fileobj = open(filename, 'w')
    try:
        await printer(link_list, addr_list, file=fileobj)
    finally:
        fileobj.close()
    return None


async def h_exec(args, link_list, addr_list, *, printer=None, loop=None):
    if None is loop:
        loop = asyncio.get_event_loop()
    if None is printer:
        printer = _DEFAULT_PRINTER
    fd_r, fd_w = os.pipe()
    fp_r = os.fdopen(fd_r, 'r')
    fp_w = os.fdopen(fd_w, 'w')
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdin=fp_r, stdout=None, loop=loop)
    finally:
        fp_r.close()
    try:
        try:
            await printer(link_list, addr_list, file=fp_w)
        finally:
            fp_w.close()
    except Exception:
        proc.terminate()
        raise
    finally:
        try:
            await proc.wait()
        except Exception:
            proc.kill()
            raise
    return None


async def monitor(callback, downtime=None,
        index=None, ifname=None, family=None, *, oneshot=False, loop=None):
    if None is loop:
        loop = asyncio.get_event_loop()
    if None is downtime or not isinstance(downtime, int):
        downtime = 0
    rth = recvs.Handle(
        nltypes.RTMGRP_LINK | nltypes.RTMGRP_IPV4_IFADDR
        | nltypes.RTMGRP_IPV6_IFADDR,
        loop=loop)
    try:
        while True:
            await rth.update()
            if 0 < downtime:
                while True:
                    try:
                        await asyncio.wait_for(
                            rth.update(False), downtime, loop=loop)
                    except asyncio.TimeoutError:
                        break
            links, addrs = rth.items(index=index, ifname=ifname, family=family)
            await callback(links, addrs)
            if oneshot:
                break
    finally:
        await rth.close()
    return None


printers = {
        'full': print_tile,
        'brief': functools.partial(print_tile, brief=True),
        'json': print_json,
        'json-brief': functools.partial(print_json, brief=True),
        'raw': print_raw,
        }


def main(args=None, namespace=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--downtime', type=int)
    parser.add_argument('-i', '--interface', action='append')
    parser.add_argument('-o', '--output',
            choices=printers.keys())
    subparsers = parser.add_subparsers(required=True, dest='action')
    subparsers.add_parser('file').add_argument('file')
    subparsers.add_parser('exec').add_argument('args', nargs='*')
    namespace = parser.parse_args(args=args, namespace=namespace)
    printer = None if None is namespace.output else printers[namespace.output]
    if 'file' == namespace.action:
        callback = functools.partial(
            h_file, namespace.file, printer=printer)
    elif 'exec' == namespace.action:
        callback = functools.partial(
            h_exec, namespace.args, printer=printer)
    else:
        raise ValueError
    core = monitor(callback, namespace.downtime, ifname=namespace.interface)
    asyncio.run(core)
    return None


if '__main__' == __name__:
    main()

