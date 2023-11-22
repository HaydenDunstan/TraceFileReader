import struct
from packet_struct import IP_Header, TCP_Header, packet, pcap_gh

class connections:
    num_of_connections = 0
    reset_connections = 0
    open_connections = 0
    complete_connections = 0
    min_time = 0.0
    mean_time = 0.0
    max_time = 0.0
    min_RTT = 0.0
    mean_RTT = 0.0
    max_RTT = 0.0
    min_packets = 0 #set high initially
    mean_packets = 0
    max_packets = 0
    min_window = 0 #in bytes
    mean_window = 0
    max_window = 0
    connections = []#of Connection class ojects

    def __init__(self) -> None:
        self.num_of_connections = 0
        self.reset_connections = 0
        self.open_connections = 0
        self.complete_connections = 0
        self.min_time = 1000.0
        self.mean_time = 0.0
        self.max_time = 0.0
        self.min_RTT = 1000.0
        self.mean_RTT = 0.0
        self.max_RTT = 0.0
        self.min_packets = 10000 #set high initially
        self.mean_packts = 0
        self.max_packets = 0
        self.min_window = 100000000000000000000000000000000000 #in bytes
        self.mean_window = 0
        self.max_window = 0
        self.connections = []#of Connection class ojects

    def add_packet(self, packet: packet):
        """
        """
        for conn in self.connections:
            if conn.compare_tuple(packet) == 1 or conn.compare_tuple(packet) == 2:
                conn.add_packet(packet)
                return None
        self.new_conn(packet)
        return None
        
    def new_conn(self, packet: packet):
        """
        """
        conn = connection()
        conn.set_tuple(packet)
        self.num_of_connections += 1
        conn.conn_num = self.num_of_connections
        
        conn.add_packet(packet)

        self.connections.append(conn)
        return None
    
    def analyze(self):
        total_duration = 0
        total_packets = 0
        total_window = 0
        window_count = 0
        total_RTT = 0
        RTT_count = 0
        for conn in self.connections:
            conn.analyze()
            if conn.reset == True:
                self.reset_connections += 1
            if (conn.fin_count >= 1)and(conn.syn_count >= 1):
                self.complete_connections += 1
                if self.min_time > conn.duration:
                    self.min_time = conn.duration
                if self.max_time < conn.duration:
                    self.max_time = conn.duration
                total_duration += conn.duration
                if self.min_packets > conn.total_count:
                    self.min_packets = conn.total_count
                if self.max_packets < conn.total_count:
                    self.max_packets = conn.total_count 
                total_packets += conn.total_count
                for p in conn.packets:
                    if self.min_window > p.TCP_header.window_size:
                        self.min_window = p.TCP_header.window_size
                    if self.max_window < p.TCP_header.window_size:
                        self.max_window = p.TCP_header.window_size
                    total_window += p.TCP_header.window_size
                    window_count += 1
                    if p.RTT_flag == True:
                        total_RTT += p.RTT_value
                        RTT_count += 1
                        if self.min_RTT > p.RTT_value:
                            self.min_RTT = p.RTT_value
                        if self.max_RTT < p.RTT_value:
                            self.max_RTT = p.RTT_value
            
        self.mean_time = round(total_duration / self.complete_connections,6)
        self.mean_packets = round(total_packets / self.complete_connections,6)
        self.mean_window = round(total_window / window_count,6)
        self.mean_RTT = round(total_RTT / RTT_count,6)#DIVISION BY ZERO?
        self.open_connections = self.num_of_connections - self.complete_connections


class connection:
    """
    """
    conn_num = 0
    src_adrs = ""
    dst_adrs = ""
    src_port = 0
    dst_port = 0
    status = ""
    syn_count = 0
    fin_count = 0
    reset = False
    start_time = 0.0
    end_time = 0.0
    duration = 0.0
    src_to_dst_count = 0
    dst_to_src_count = 0
    total_count = 0
    bytes_from_src = 0
    bytes_from_dst = 0
    total_bytes = 0 #still need
    packets = []
    og_seq_in = 0
    og_seq_out = 0
    complete = False

    def __init__(self):
        self.conn_num = 0
        self.src_adrs = ""
        self.dst_adrs = ""
        self.src_port = 0
        self.dst_port = 0
        self.status = ""
        self.syn_count = 0
        self.fin_count = 0
        self.reset = False
        self.start_time = 0.0
        self.end_time = 0.0
        self.duration = 0.0
        self.src_to_dst_count = 0
        self.dst_to_src_count = 0
        self.total_count = 0
        self.bytes_from_src = 0
        self.bytes_from_dst = 0
        self.total_bytes = 0
        self.packets = []
        self.og_seq_in = -1
        self.og_seq_out = -1
        self.complete = False

    def compare_tuple(self, packet: packet)->int:
        """
        return 1 if src to dst match, 2 if dest to src match, otherwise 0
        """
        if(self.src_adrs == packet.IP_header.src_ip and self.dst_adrs == packet.IP_header.dst_ip and self.src_port == packet.TCP_header.src_port and self.dst_port == packet.TCP_header.dst_port):
            return 1
        elif (self.src_adrs == packet.IP_header.dst_ip and self.dst_adrs == packet.IP_header.src_ip and self.src_port == packet.TCP_header.dst_port and self.dst_port == packet.TCP_header.src_port):
            return 2
        else:
            return 0
        
    def set_tuple(self, packet: packet):
        self.src_adrs = packet.IP_header.src_ip
        self.dst_adrs = packet.IP_header.dst_ip
        self.src_port = packet.TCP_header.src_port
        self.dst_port = packet.TCP_header.dst_port
        self.start_time = packet.timestamp
        self.og_seq_out = packet.TCP_header.seq_num
        
    def add_packet(self, packet: packet):
        if self.compare_tuple(packet) == 1:
            self.src_to_dst_count +=1
            self.bytes_from_src += packet.data_bytes
            packet.TCP_header.relative_seq_num(self.og_seq_out)
            if packet.TCP_header.flags["ACK"] == 1:
                packet.TCP_header.relative_ack_num(self.og_seq_in)
        elif self.compare_tuple(packet) == 2:
            if self.dst_to_src_count == 0:
                self.og_seq_in = packet.TCP_header.seq_num
            self.dst_to_src_count +=1
            self.bytes_from_dst += packet.data_bytes
            packet.TCP_header.relative_seq_num(self.og_seq_in)
            if packet.TCP_header.flags["ACK"] == 1:
                packet.TCP_header.relative_ack_num(self.og_seq_out)
        if packet.TCP_header.flags["SYN"] == 1:
            self.syn_count += 1
        if packet.TCP_header.flags["FIN"] == 1:
            self.fin_count += 1
            self.end_time = packet.timestamp
        if packet.TCP_header.flags["RST"] == 1:
            self.reset = True
        self.duration = round(self.end_time - self.start_time,6)

        self.packets.append(packet)

    def find_RTT(self):
        for p1 in self.packets:
            for p2 in self.packets:
                if p1 == p2:
                    """DO NOTHING"""
                elif p1.timestamp > p2.timestamp:
                    """DO NOTHING"""
                elif(p1.RTT_flag == True):
                    """DO NOTHING"""
                elif(p2.TCP_header.flags["ACK"] == 0):
                    """DO NOTHING"""
                elif (p2.TCP_header.ack_num) == (p1.TCP_header.seq_num + p1.data_bytes):
                    p1.get_RTT_value(p2)

    def analyze(self):
        if self.reset == True:
            self.status = "S" + str(self.syn_count) + "F" + str(self.fin_count) + "/R"
        else:
            self.status = "S" + str(self.syn_count) + "F" + str(self.fin_count)
        self.total_count = self.src_to_dst_count + self.dst_to_src_count
        self.total_bytes = self.bytes_from_src +self.bytes_from_dst
        if (self.fin_count >= 1)and(self.syn_count >= 1):
            self.complete = True
        self.find_RTT()
