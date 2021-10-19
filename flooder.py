#!/usr/bin/env python3
from scapy.all import *
import hashlib

def main():
    interface = "lo"
    watchdog_ip = "127.0.0.1"
    prefix = b'witness_me'
    secret = b'a' * 65400

    kick = IP(dst=watchdog_ip) / ICMP(type=19)
    socket = conf.L3socket()
    h = hashlib.new('sha512')
    h.update(prefix + secret)
    kick.add_payload(prefix + secret + h.digest()[:-1] + b'a')
    kick.show()
    send(kick, verbose=False, iface=interface, loop=1, inter=0.0000001, socket=socket)

if __name__ == '__main__':
    main()
