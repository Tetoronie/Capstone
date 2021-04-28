from scapy.all import *
from scapy.contrib.bgp import *
from scapy.layers.inet import IP, TCP
load_contrib('bgp')

#dIP="192.168.20.1"
#sIP="192.168.20.2"
#dstPort=24333
#srcPort=179

# Pass seq num, ack num, and source port on cmd line

base= IP(src="192.168.4.1", dst="192.168.20.1", proto=6, ttl=1)
tcp = TCP(dport=179, sport=int(sys.argv[3]), seq=int(sys.argv[1]), ack=int(sys.argv[2]), flags="PA")

#Type 3 is notification, marker is used for authentication, max hex for no auth(32 fs)
BGPHeader = BGPHeader(type=2, marker=0xffffffffffffffffffffffffffffffff)

Origin = 0
Path = ['1000', '1050']
nextHop = '192.168.4.2'
nlriV = BGPNLRI_IPv4(prefix='172.16.0.0')

BGPUp = BGPUpdate(path_attr=[BGPPathAttr(type_flags=64, type_code=5, attribute=[BGPPAOrigin=0, BGPPAASPath=['1000','1050'], BGPPANextHop='192.168.4.2'], nlri=BGPNLRI_IPv4(prefix='172.16.0.0/16'))

BGPUpB = BGPUpdate(path_attr=[BGPPathAttr(type_flags=64, type_code=5, attribute=BGPPALocalPref(local_pref=100))], nlri=BGPNLRI_IPv4(prefix='172.16.0.0/16'))


#pkt=IP(dst=dIP,src=sIP,ttl=1) / TCP(dport=dstPort,sport=srcPort) / BGPHeader / BGPNotif
#pkt.show2()

packet = base / tcp / BGPHeader / BGPUp
packet.show()

#BGPPALocalPref(local_pref=100), 
