How it works:

In order to succcessfuly flood the watchdog client, it involved us modifying the existing client in a number of ways. Firstly we changed the client so
that instead of sending packets at a nice interval, it sends packets non-stop. This involved the removal of:

'sleep(0.5)'

And the inclusion of:

'loop =1' and 'inter= 0.00000001' within the send message. This sent packets continuously at a very fast rate.

Within the client, we also changed the content of the 'kick' itself, so that it would fail at the last possible check. By looking that the watchdog.rs code,
we were able to see that the last check, is for the validity of the hash. This meant that we wanted the length of the hash, the prefix, and the secret 
to all be correct. We made the hash check fail by changing the last byte to be incorrect.

We also changed how we sent the kick. Previously each time a 'kick' message was sent, it created a new socket, and tore down the old one. In order to speed up
how fast our packets were sent, we provided a pre-existing socket so that there was less overhead in the constant creation and removal of sockets. We also made
the packets considerably larger by padding lots of useless bytes into the 'secret' value.


Obstacles:
The first issue we ran into was in the successful running of the watchdog client, but this was successfuly fixed through some Docker configuration.

We were easily able to get our client to send packets that failed in the right place, but we did run into issues with how fast our packets were being sent.
Despite attempting to send packets rapidly in an number of manners (including: sending packets in a list, utilizing while loops, and even fragmenting packets), we
were unsuccessful.  We finally realized that each time send was being called it was creating a new socket, which severely limited our ability to send fast. By 
providing a socket, we were able to remove that overhead, and send significantly more packets per second.

Our packet speed was pretty much the only issue that really stumped us.

The nature of our code means it sometimes varies with how fast it causes the watchdog to fail. Sometimes it fails in 3 seconds, sometimes it takes up to a minute or 2.

