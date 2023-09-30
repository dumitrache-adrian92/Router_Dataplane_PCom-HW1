Router dataplane implementation written in C. Capable of parsing, forwarding
and responding to incoming IPv4 packets using the ARP and ICMP protocols.
Since this is only a dataplane, a static routing table has to be used to
determine next hops. You can find one in this repository along with a
corresponding virtual topology. These can be used to play with the router.

Like this:
```bash
sudo python3 checker/topo.py
make run_router0 // in the router 0 terminal
make run_router1 // in the router 1 terminal
```
And then use networking commands between hosts like ping to communicate:
```
ping h1 // from host2
ping h3 // from host0
etc.
```
