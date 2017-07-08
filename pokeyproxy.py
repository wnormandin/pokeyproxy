#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# * * * * * * * * * * * * * * * * * * * *
#   pokeyproxy: a simple TCP proxy
#   Requires python3
#
#   Help & Usage:
#   $ python3 pokeyproxy.py -h
#
# * * * * * * * * * * * * * * * * * * * *
#
#   MIT License
#
#   Copyright (c) 2017 William Normandin
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.
#
# * * * * * * * * * * * * * * * * * * * *

import signal
import socket
import threading
import sys
import argparse


if sys.version_info[0] < 3:
    # Python 3 required for command line execution
    raise AssertionError("Must use Python 3")

this = sys.modules[__name__]

def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument('--local-port', type=int, help='Specify bind port (default = 8520)',
                        default=8520)
    parser.add_argument('--remote-port', type=int, help='Specify the remote port')
    parser.add_argument('--remote-host', type=str, help='Specify the remote host')
    parser.add_argument('--receive-first', action='store_true', help='Connect and receive before sending data')
    parser.add_argument('--nocolor', action='store_true', help='Skip colors in output')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--timeout', type=float, help='Request timeout in s (Default=3s)', default=3)
    return parser.parse_args()

def cprint(val, col=None, verbose=False):
    if not args.verbose and verbose:
        return
    if col==None:
        msg = val
    else:
        msg = color_wrap(val, col)
    print(msg)

def color_wrap(val, col):
    if args.nocolor:
        return str(val)
    return ''.join([col, str(val), Color.END])


class InterruptHandler:

    ''' Interrupt Handler as context manager '''

    def __init__(self, sig=signal.SIGINT):
        self.sig = sig

    def __enter__(self):
        self.interrupted = False
        self.released = False
        self.sig_orig = signal.getsignal(self.sig)

        def handler(signum, frame):
            self.release()
            self.interrupted = True

        signal.signal(self.sig, handler)
        return self

    def __exit__(self, type, value, tb):
        self.release()

    def release(self):
        if self.released:
            return False
        signal.signal(self.sig, self.sig_orig)
        self.released = True
        return True


class Color:
    BLACK_ON_GREEN = '\x1b[1;30;42m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    MSG = '\x1b[1;32;44m'
    ERR = '\x1b[1;31;44m'
    TST = '\x1b[7;34;46m'

def hexdump(src, length=16):
    result = []
    digits = 4
    for i in range(0, len(src), length):
        s = src[i:i+length]
        hexa = b' '.join(['{0:0{1}X}'.format(ord(x), digits) for x in s])
        text = b''.join([ x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append(b'{0:04X}    {1:-{2}}    {3}' % (i, length*(digits+1), hexa, text))
    cprint(b'\n'.join(result), Color.BLUE)

def receive_from(cxn):
    buff = ''
    cprint(' -  Setting timeout to {}s'.format(args.timeout), Color.BLUE, True)
    cxn.settimeout(args.timeout)
    failed = 0
    try:
        while True:
            if failed % 3 == 0:
                cprint(' -  3 cxn.recv() errors, exiting', Color.BLUE, True)
                break
            data = cxn.recv()
            if not data:
                failed += 1
            else:
                buff += data
    except socket.timeout:
        cprint(' -  Socket timeout', Color.BLUE, True)
    except KeyboardInterrupt:
        pass
    except:
        raise
    return buff

def request_handler(buff):
    # Not yet implemented, packet modifications, etc can go here
    return buff

def response_handler(buff):
    # Not yet implemented, modify responses destined to localhost
    return buff

def proxy_handler(c_sock, remote_host, remote_port, recv_first):
    remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_sock.connect((remote_host, remote_port))

    # Handle receive_first if True
    if recv_first:
        r_buff = receive_from(remote_sock)
        hexdump(r_buff)
        r_buff = response_handler(r_buff)
        if len(r_buff):
            cprint('[<] Sending {} bytes to localhost'.format(len(r_buff)), Color.GREEN)
            c_sock.send(r_buff)

    # Start proxy loop
    while True:
        try:
            l_buff = receive_from(c_sock)
            if len(l_buff):
                cprint('[>] Received {} bytes from localhost'.format(len(l_buff), Color.GREEN))
                hexdump(l_buff)
                l_buff = response_handler(l_buff)
                remote_sock.send(l_buff)
                cprint('[>] Sent to remote', Color.GREEN)
            r_buff = receive_from(remote_sock)
            if len(r_buff):
                cprint('[<] Received {} bytes from remote'.format(len(r_buff), Color.GREEN))
                hexdump(r_buff)
                r_buff = response_handler(r_buff)
                c_sock.send(r_buff)
                cprint('[<] Sent to localhost', Color.GREEN)
            if not len(l_buff) and not len(r_buff):
                safe_close(c_sock)
                safe_close(remote_sock)
                cprint('[!] No more data, closing connections', Color.GREEN)
                break
        except KeyboardInterrupt:
            safe_close(c_sock)
            safe_close(remote_sock)
            break

def safe_close(cxn):
    cxn.shutdown(1)
    cxn.close()


def server_loop(args):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server_sock.bind(('', args.local_port))
    except:
        cprint('[!] Failed to bind to localhost:{}'.format(args.local_port), Color.ERR)
        cprint(' -  Check permissions and for active sockets', Color.BLUE, True)
        raise
        sys.exit(1)
    cprint('[*] Listening on port {}'.format(args.local_port), Color.GREEN)
    server_sock.listen(args.timeout)
    with InterruptHandler() as h:
        while not h.interrupted:
            client_sock, addr = server_sock.accept()
            cprint('[>] Received incoming connection from {}:{}'.format(*addr), Color.GREEN)
            proxy_thread = threading.Thread(target=proxy_handler,
                                args=(client_sock, args.remote_host,
                                args.remote_port, args.receive_first))
            proxy_thread.start()
        client_sock.close()
        server_sock.close()

if __name__ == '__main__':
    this.args = cli()
    server_loop(args)
