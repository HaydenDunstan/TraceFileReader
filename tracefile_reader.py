from packet_struct import IP_Header, TCP_Header, packet, pcap_gh
import sys
from struct import *
from connections_struct import connections, connection

def main():
    """
    In: .cap file to be read
    """
    #read file
    packets = parse_and_process()
    #analyze and package
    connections = analyze_packets(packets)
    #print output
    print_output(connections)
    #return
    return None

def parse_and_process() -> list:
    '''
    In: void
    Out: a list of [global header data, [packet header data, packet],[packet header data, packet],[packet header data, packet],etc]
    read an the file on the command line
    '''
    try: #Check if too many arguments were passed
        str(sys.argv[2])
        print("Error: Too Many arguments")
        exit()
    except IndexError:
        try:
            filename = str(sys.argv[1])
        except IndexError: #Check if no argument was passed
            print("Error: No Filename Given")
            exit()
        #open file and get global header
        try:
            f = open(filename, "rb")
        except FileNotFoundError:
            print("Error: No such file or directory")
            exit()
        global_h = f.read(24)
        #read global header
        gh = pcap_gh(global_h)

        #loop to read all packets
        i = 1#packet No.
        packet_list = []
        while 1:
            #read next 16 bytes for packet header 
            ph = f.read(16)
            #get header fields
            ts_sec = ph[0:4]
            ts_sec = swap_endianness(ts_sec,gh.endian)
            ts_usec = ph[4:8]
            ts_usec = swap_endianness(ts_usec,gh.endian)
            incl_len =int.from_bytes(ph[8:12], byteorder=gh.endian, signed=False)
            orig_len =int.from_bytes(ph[12:16], byteorder=gh.endian, signed=False)
            #test if no more packets
            if  (incl_len==0):
                break
            #make a packet struct and start setting parameters
            if i == 1:
                seconds = unpack('>I',ts_sec)[0]
                microseconds = unpack('>I',ts_usec)[0]
                orig_time = round(microseconds*0.000001 + seconds,6)
            p = packet(gh)
            p.packet_No_set(i)
            p.timestamp_set(ts_sec, ts_usec, orig_time)
            #read the next incl_len for packet data
            pd = f.read(incl_len)
            #set IP header values
            p.IP_header = read_IP_header(pd, p)
            #set TCP header values
            p.TCP_header =read_TCP_header(pd, p)
            #set num of data bytes
            p.data_bytes = p.IP_header.total_len - p.IP_header.ip_header_len - p.TCP_header.data_offset
            #print(orig_len, p.IP_header.ip_header_len, p.TCP_header.data_offset)

            i+=1
            packet_list.append(p)
            
        #print(len(packet_list))
        return packet_list

def read_IP_header(packet, p):
    """
    read IP header from a PCAP packet
    """
    ip = IP_Header()
    src = packet[26:30]
    #src = swap_endianness(src, p.global_header.endian)
    dest = packet[30:34]
    #dest = swap_endianness(dest, p.global_header.endian)
    ip.get_IP(src, dest)
    ip.get_header_len(packet[14:15])
    ip.get_total_len(packet[16:18])
    return ip

def read_TCP_header(packet, p: packet):
    """
    read_TCP_header
    """
    tcp = TCP_Header()
    start = p.IP_header.ip_header_len + 14
    tcp.get_src_port(packet[start:start+2])
    tcp.get_dst_port(packet[start+2:start+4])
    tcp.get_seq_num(packet[start+4:start+8])
    tcp.get_ack_num(packet[start+8:start+12])
    tcp.get_flags(packet[start+13:start+14])
    tcp.get_window_size(packet[start+14:start+15],packet[start+15:start+16])
    tcp.get_data_offset(packet[start+12:start+13])
    return tcp

def analyze_packets(packets: list)->connections:
    """
    In:  a list of packet objects
    Out: A connections class that will include all of the connections in
    the cap file and the info necessary for output
    """
    conns = connections()
    for packet in packets:
        conns.add_packet(packet)
    conns.analyze()

    return conns

def print_output(conns: connections)->None:
    """
    In: A connections class that will include all of 
        the necessary info for output
    Out: nothing
    """
    print("\n\n\n\n\nA) Total number of connections: ", conns.num_of_connections, "\n________________________________________________\n\nB) Connection's details\n\n",sep="",end="")
    for conn in conns.connections:
        if conn == conns.connections[0]:
            """do nothing"""
        else:
            print("++++++++++++++++++++++++++++++++\n",sep="",end="")
        print("Connection ", conn.conn_num,":\nSource Address: ",conn.src_adrs,"\nDestination Address: ",sep="",end="")
        print(conn.dst_adrs,"\nSource Port: ",conn.src_port,"\nDestination Port: ",conn.dst_port,sep="",end="")
        print("\nStatus: ", conn.status,sep="",end="\n")
        if conn.complete == True:
            print("Start time: ", conn.start_time, " seconds\nEnd Time: ", conn.end_time,sep="",end="")
            print(" seconds\nDuration: ",conn.duration," seconds\nNumber of packets sent from Source to Destination: ",sep="",end="")
            print(conn.src_to_dst_count,"\nNumber of packets sent from Destination to Source: ",conn.dst_to_src_count,sep="",end="")
            print("\nTotal number of packets: ",conn.total_count,"\nNumber of data bytes sent from Source to Destination: ",sep="",end="")
            print(conn.bytes_from_src,"\nNumber of data bytes sent from Destination to Source: ",conn.bytes_from_dst,sep="",end="")
            print("\nTotal number of data bytes: ",conn.total_bytes,"\nEND\n",sep="",end="")
    print("________________________________________________\n\nC) General\nTotal number of complete TCP connections: ",sep="",end="")
    print(conns.complete_connections,"\nNumber of reset TCP connections: ", conns.reset_connections,sep="",end="")
    print("\nNumber of TCP connections that were still open when the trace capture ended: ",conns.open_connections,sep="",end="\n")
    print("________________________________________________\n\nD) Complete TCP connections\n\nMinimum time duration: ",conns.min_time,sep="",end="")
    print(" seconds\nMean time duration: ",conns.mean_time," seconds\nMaximum time duration: ",conns.max_time," seconds\n\n",sep="",end="")
    #removed temporarily while working on a fix
    #print("Minimum RTT value: ",conns.min_RTT,"\nMean RTT value: ",conns.mean_RTT,"\nMaximum RTT value: ",conns.max_RTT,"\n\n",sep="",end="")
    print("Minimum number of packets including both send/received: ",conns.min_packets,"\nMean number of packets including both send/received: ", conns.mean_packets,"\n",sep="",end="")
    print("Maximum number of packets including both send/received: ",conns.max_packets,"\n\nMinimum receive window size including both send/received: ", "{:.8f}".format(conns.min_window)," bytes\nMean receive window size including both send/received: ",sep="",end="")
    print(conns.mean_window," bytes\nMaximum receive window size including both send/received: ",conns.max_window,sep="",end="")
    print("\n________________________________________________\n\n\n\n\n\n",sep="",end="")

def swap_endianness(data, endian):
    if endian == 'little':
        return data[::-1]

main()