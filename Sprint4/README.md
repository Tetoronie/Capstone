In this bgpReset.py packet, I am targeting the VyOS-2 Router(192.168.4.1) and using the source of VyOS-5(192.168.4.2) to try and trick the target. The BGP header type is '3' to indicate that this is a NOTIFICATION message. In the NOTIFICATION message, I pass the 'error code' of 6 which represents 'cease', telling the router to terminate its currently peer session. The 'error subcode' is set to 4 to represent "administratively reset"