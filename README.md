
# Packet Connector
A packets connector allows conversion of packets from different interface and different formats (tcp client/server, netmap, pcap). This project aim to implement pcap packet read/written from/to pcap interfaces and files.

**EXTRA**: Added a test funtionality through virtual interface (see veth) that generates ARP packets.

### Known issues
- The pcap inject function cannot write to the NIC a packet whose size is greater than the MTU. 
- This way some asymmetry arises: fragmented packets are delivered to the application already reassembled by the NIC and put in the pconn queue, thus having occasionally large sizes.
- In the opposite direction (writing those received packets from the queue to the NIC through the inject function), instead, packets are not fragmented: they are simply truncated, thus they become corrupted when sent over the network
