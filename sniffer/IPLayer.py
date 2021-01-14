import struct
import socket
import time
import queue
import threading

from .PacketProducer import RAW_PACKET_QUEUE, IP_TYPE_TO_COMMON_NAME

ip_fragment_table = {}
IP_PRODUCER_SHUTDOWN_EVENT = threading.Event()
IP_PAYLOADS = queue.Queue()
IP_RECONSTRUCTION_TIME_LIMIT = 10

def get_ipv4_header_struct():
	"""Create the IPv4 struct header format for parsing"""
	fmt =  "!" #network byte order
	fmt += "B" #version (4 bits) + internet header length (4 bits)
	fmt += "B" #DSCP (6 bits) + ECN (2 bits)
	fmt += "H" #total pkt length (2 bytes --- unsigned short)
	fmt += "H" #identification (2 bytes --- unsigned short)
	fmt += "H" #flags (3 bits) + fragment offset (13 bits)
	fmt += "B" #time to live (1 byte --- unsigned char)
	fmt += "B" #protocol (1 byte --- unsigned char)
	fmt += "H" #header checksum (2 bytes --- unsigned short)
	fmt += "I" #source ip (4 bytes --- unsigned int)
	fmt += "I" #destination ip (4 bytes --- unsigned int)
	return fmt

class IPv4Layer(object):
	"""IPv4 header parser"""
	def __init__(self, packet):
		assert len(packet) >= 20 #the IPv4 layer is 20 bytes at least
		version_ihl, dscp_ecn, packet_length, identification, flags_fragment_offset, ttl, protocol, header_checksum, src_ip, dst_ip = struct.unpack(get_ipv4_header_struct(), packet[:20])
		self.version = version_ihl >> 4 
		assert self.version == 4 #the version field cannot have other value than 4
		self.header_length = version_ihl & 0b00001111
		self.dscp = dscp_ecn >> 2
		self.ecn = dscp_ecn & 0b00000011
		self.total_length = packet_length
		self.identification = identification
		self.flags = flags_fragment_offset >> 13
		self.fragment_offset = flags_fragment_offset & 0b0001111111111111
		self.ttl = ttl
		self.protocol = protocol
		self.header_checksum = header_checksum
		self.src_ip = socket.inet_ntoa(struct.pack('!I', src_ip))
		self.dst_ip = socket.inet_ntoa(struct.pack('!I', dst_ip))
		options_size = self.header_length*4 - 20
		self.options = packet[20:20+options_size]
		self.content = packet[20+options_size:]


IP_TYPE_PARSERS = {
	"IPv4": IPv4Layer
}

def produce_ip_fragments_and_reassemble_them(sleep_time = 0.5):
	"""Consume the raw packets, parse their ip layer contents and reassemble the payload via RFC791 inspired algotihm"""
	while not IP_PRODUCER_SHUTDOWN_EVENT.is_set():
		#first, purge old connection infromation
		for src_ip in list(ip_fragment_table.keys()):
			for dst_ip in list(ip_fragment_table[src_ip].keys()):
				for transfer_id in list(ip_fragment_table[src_ip][dst_ip].keys()):
					if time.time() - ip_fragment_table[src_ip][dst_ip][transfer_id]["last_modified"] < IP_RECONSTRUCTION_TIME_LIMIT:
						del ip_fragment_table[src_ip][dst_ip][transfer_id]

				if len(ip_fragment_table[src_ip][dst_ip].keys()) == 0:
					del ip_fragment_table[src_ip][dst_ip]

			if len(ip_fragment_table[src_ip].keys()):
				del ip_fragment_table[src_ip]

		if RAW_PACKET_QUEUE.empty():
			time.sleep(sleep_time)
			continue

		packet, ip_info, ip_type = RAW_PACKET_QUEUE.get()

		if not IP_TYPE_TO_COMMON_NAME[ip_type] in IP_TYPE_PARSERS:
			print("[!!!] IP packet of type unknown received")
			continue

		try:
			ip_packet = IP_TYPE_PARSERS[IP_TYPE_TO_COMMON_NAME[ip_type]](packet)
		except Exception as e:
			continue

		if ip_packet.protocol != 0x06: #TCP has a protocol identifier of 0x06, since HTTP only uses TCP (only HTTP3 uses it, but, not even HTTP2 is widely used) the other protocols will be ignored
			continue

		if (ip_packet.fragment_offset == 0) and not (ip_packet.flags & 1): #fragment offset is 0 and the more fragments flag is set
			IP_PAYLOADS.put(( ip_packet.src_ip, ip_packet.dst_ip, ip_packet.content ))
		else:
			if not ip_packet.src_ip in ip_fragment_table:
				ip_fragment_table[ip_packet.src_ip] = {}

			if not ip_packet.dst_ip in ip_fragment_table[ip_packet.src_ip]:
				ip_fragment_table[ip_packet.src_ip][ip_packet.dst_ip] = {}

			if not ip_packet.identification in ip_fragment_table[ip_packet.src_ip][ip_packet.dst_ip]:
				ip_fragment_table[ip_packet.src_ip][ip_packet.dst_ip][ip_packet.identification] = {
					"data": [],
					"last_modified": time.time(),
					"total_data_length": 0,
					"total_received": 0
				}

			fragment_info = ip_fragment_table[ip_packet.src_ip][ip_packet.dst_ip][ip_packet.identification]
			fragment_info["data"].insert(ip_packet.fragment_offset, ip_packet.content)
			fragment_info["total_received"] += len(ip_packet.content)
			fragment_info["last_modified"] = time.time()
			if not (ip_packet.flags & 1): #if the more fragments flag is not set
				fragment_info["total_data_length"] = len(ip_packet.content) + (8*ip_packet.fragment_offset)

			if fragment_info["total_data_length"] != 0 and fragment_info["total_data_length"] == fragment_info["total_received"]:
				IP_PAYLOADS.put(( ip_packet.src_ip, ip_packet.dst_ip, b"".join(fragment_info["data"]) ))	
				del ip_fragment_table[ip_packet.src_ip][ip_packet.dst_ip][ip_packet.identification]


def start_processing_raw_packets(sleep_time = 0.5):
	processing_thread = threading.Thread(target = produce_ip_fragments_and_reassemble_them, name = "RAW packet processor", args = (sleep_time,))
	processing_thread.daemon = True
	processing_thread.start()
