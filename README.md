# IP-Flooding

## Overview:

    1. Experiment with packet construction tools
    2. Exploit a network service vulnerable to flooding-based denial-of-service

## Network Watchdog
This projects attacks a network watchdog. This watchdog is responsible for supervising a user-facing service. That service must periodically “kick” the watchdog in order to demonstrate that it is still healthy. Otherwise, the watchdog will terminate that service. The goal here is to force the watchdog to drop a kick, causing it to terminate the supervised service and thus create a denial-of-service (DoS).

The watchdog protocol is as follows:
    
    S -> W : witness_me||K||H
    
Where K is an optional secret and H is a SHA-512 hash of the string witness_me and the secret, if any. This payload is encapsulated in an ICMP message with type 19 and code 0. 

flooder.py is an attack that floods the watchdog to cause a denial of service.
