import struct
import enum
import threading
import time
import queue
from .IPLayer import IP_PAYLOADS

class TCP_STATE(enum.Enum):
	"""An enum with the possible states, not all are used"""
	CLOSED = 0
	LISTEN = 1
	SYN_SENT = 2
	SYN_RECEIVED = 3
	ESTABLISHED = 4
	CLOSE_WAIT = 5
	LAST_ACK = 6
	FIN_WAIT_1 = 7
	FIN_WAIT_2 = 8
	CLOSING = 9
	TIME_WAIT = 10

TRANSPARENT_SOCKETS = []
TCP_TIMEOUT = 60
TCP_PRODUCER_SHUTDOWN_EVENT = threading.Event()
NEW_SOCK_QUEUE = queue.Queue()


def get_tcp_header_struct():
	"""Create the TCP struct header format for parsing"""
	fmt = "!" #network byte order
	fmt += "H" #source port (2 bytes --- unsigned short)
	fmt += "H" #destination port (2 bytes --- unsigned short)
	fmt += "I" #sequence number (4 bytes --- unsigned int)
	fmt += "I" #acknowlegement (4 bytes --- unsigned int); if the ack flag is not set, then the value is still present but has no meaning
	fmt += "H" #data offset (4 bits) + reserved (3 bits) + flags (9 bits) (2 bytes --- unsigned short)
	fmt += "H" #window size (2 bytes --- unsigned short)
	fmt += "H" #checksum (2 bytes --- unsigned short)
	fmt += "H" #urgent pointer (2 bytes --- unsigned short); if the urg flag is not set, then the value is still present but has no meaning
	return fmt

class TCPFlags(object):
	"""Parse and abstract away the TCP flags"""
	def __init__(self, flags):
		assert flags >= 0b000000000 and flags <= 0b111111111
		self.FIN = flags & 1; flags >>= 1
		self.SYN = flags & 1; flags >>= 1
		self.RST = flags & 1; flags >>= 1
		self.PSH = flags & 1; flags >>= 1
		self.ACK = flags & 1; flags >>= 1
		self.URG = flags & 1; flags >>= 1
		self.ECE = flags & 1; flags >>= 1
		self.CWR = flags & 1; flags >>= 1
		self.NS = flags & 1

class TCPLayer(object):
	"""TCP header parser"""
	def __init__(self, packet):
		assert len(packet) >= 20
		self.src_port, self.dst_port, self.seq, self.ack, data_offset__reserved__flags, self.window_size, self.checksum, self.urgent_pointer = struct.unpack(get_tcp_header_struct(), packet[:20])
		self.data_offset = data_offset__reserved__flags >> 12
		self.flags = TCPFlags(data_offset__reserved__flags & 0b0000000111111111)
		self.options = packet[20:(4*self.data_offset)-20]
		self.content = packet[4*self.data_offset:]

def modulo(a, m):
	if a >= 0:
		return a % m
	else:
		return modulo(m-a, m)

class TransparentSocket(object):
	"""Represents an ungoing connection, simulates a socket but only has the recv function"""
	def __init__(self, src_ip, src_port, dst_ip, dst_port, state = TCP_STATE.CLOSED):
		self.src_ip = src_ip
		self.src_port = src_port
		self.dst_ip = dst_ip
		self.dst_port = dst_port
		self.state = state
		self.pending_buffer = b""
		self.data_buffer = b""
		self.data_buffer_lock = threading.Lock()
		self.seq = None
		self.ack = None
		self.init_seq = None
		self.init_ack = None
		self.last_action = time.time()

	def queue_data(self, seq, data):
		"""Puts the data from a TCP packet with data into a temporary buffer"""
		self.pending_buffer += self.pending_buffer[:modulo(seq-self.seq, 2**32)] + data
		self.seq += len(data)

	def set_state(self, state):
		"""Sets the state of a TransparentSocket, if the state is set to closed, then it flushes the buffer to the acknowledged buffer"""
		if state == TCP_STATE.CLOSED:
			with self.data_buffer_lock:
				self.data_buffer += self.pending_buffer
				self.pending_buffer = b""
		self.state = state

	def acknowledge(self, ack):
		"""Flushes part of the temporary buffer to the acknowledged buffer"""
		size = modulo(ack - self.ack, 2**32)
		if size < 0:
			size = (2**32) - self.ack + ack
		with self.data_buffer_lock:
			self.data_buffer += self.pending_buffer[:size]
		self.pending_buffer = self.pending_buffer[size:]
		self.ack = ack

	def recv(self, size):
		"""Reads part of the acknowledged buffer"""
		while len(self.data_buffer) == 0 and self.state != TCP_STATE.CLOSED:
			time.sleep(0.1)
		with self.data_buffer_lock:
			data = self.data_buffer[:size]
			self.data_buffer = self.data_buffer[size:]
		return data

	def is_closed(self):
		"""Just a simple check, used to hide the TCP_STATE enum from other scripts"""
		return self.state == TCP_STATE.CLOSED

	def recv_until(self, delim):
		"""Reads from the acknowledged buffer untill a delimitator is seen"""
		while len(self.data_buffer) == 0 and self.state != TCP_STATE.CLOSED:
			time.sleep(0.1)
		substream = None
		with self.data_buffer_lock:
			if delim in self.data_buffer:
				substream = self.data_buffer[: self.data_buffer.index(delim)+len(delim)]
				self.data_buffer = self.data_buffer[self.data_buffer.index(delim)+len(delim):]
			else:
				substream = self.data_buffer
				self.data_buffer = b""
		return substream


def get_transparent_socket(src_ip, src_port, dst_ip, dst_port):
	"""Finds a transparent socket identified by source ip, source port, destination ip, destination port"""
	for tsocket in TRANSPARENT_SOCKETS:
		if tsocket.src_ip == src_ip and tsocket.dst_ip == dst_ip and tsocket.src_port == src_port and tsocket.dst_port == dst_port:
			tsocket.last_action = time.time()
			return tsocket
	return None

def process_ip_payloads(sleep_time = 0.5):
	"""Processes all new TCP packets, since raw sockets send data out of order, a packet might be reprocessed more times"""
	while not TCP_PRODUCER_SHUTDOWN_EVENT.is_set():
		#cleanup code
		for tsocket in TRANSPARENT_SOCKETS[::]:
			if time.time()-tsocket.last_action > TCP_TIMEOUT:
				tsocket.set_state(TCP_STATE.CLOSED)
				TRANSPARENT_SOCKETS.remove(tsocket)

		if IP_PAYLOADS.empty():
			continue

		src_ip, dst_ip, payload = IP_PAYLOADS.get()
		try:
			packet = TCPLayer(payload)
		except Exception as e:
			print("[!!!] Invalid TCP packet received", e)
			continue

		tdst = get_transparent_socket(src_ip, packet.src_port, dst_ip, packet.dst_port)
		tsrc = get_transparent_socket(dst_ip, packet.dst_port, src_ip, packet.src_port)

		if tsrc is None and tdst is None:
			tdst = TransparentSocket(src_ip, packet.src_port, dst_ip, packet.dst_port)
			tsrc = TransparentSocket(dst_ip, packet.dst_port, src_ip, packet.src_port)
			if packet.flags.SYN and not packet.flags.ACK: #SYN sent from the source
				tsrc.set_state(TCP_STATE.SYN_SENT)
				tdst.set_state(TCP_STATE.LISTEN)
				tdst.seq = packet.seq + 1
				TRANSPARENT_SOCKETS.append(tsrc)
				TRANSPARENT_SOCKETS.append(tdst)
				NEW_SOCK_QUEUE.put((tdst, tsrc))
				continue
		else:

			if packet.flags.SYN and packet.flags.ACK and tdst.state == TCP_STATE.SYN_SENT: #SYN-ACK response from the server
				tsrc.set_state(TCP_STATE.SYN_RECEIVED)
				tdst.seq = packet.seq + 1
				continue

			#ACK response from the client
			if packet.flags.ACK and tdst.state == TCP_STATE.SYN_RECEIVED and packet.seq == tdst.seq and packet.ack == tsrc.seq and len(packet.content) == 0:
				tsrc.set_state(TCP_STATE.ESTABLISHED)
				tdst.set_state(TCP_STATE.ESTABLISHED)
				tdst.ack = tsrc.seq
				tsrc.ack = tdst.seq
				continue

			if packet.flags.RST: #close the connection on RST
				tsrc.set_state(TCP_STATE.CLOSED)
				tdst.set_state(TCP_STATE.CLOSED)
				if tsrc in TRANSPARENT_SOCKETS:
					TRANSPARENT_SOCKETS.remove(tsrc)
				if tdst in TRANSPARENT_SOCKETS: 
					TRANSPARENT_SOCKETS.remove(tdst)
				continue

			#handle data packets and ACKS
			if tdst.state == TCP_STATE.ESTABLISHED and tsrc.state == TCP_STATE.ESTABLISHED and packet.flags.ACK and tdst.seq == packet.seq:
				if len(packet.content) > 0:
					tdst.queue_data(packet.seq, packet.content)
					continue
				else:
					tsrc.acknowledge(packet.ack)
					if packet.flags.FIN:
						tsrc.set_state(TCP_STATE.CLOSED)
						tdst.set_state(TCP_STATE.CLOSED)
						TRANSPARENT_SOCKETS.remove(tsrc)
						TRANSPARENT_SOCKETS.remove(tdst)
					continue
			IP_PAYLOADS.put((src_ip, dst_ip, payload)) #cicle the unused packets, raw sockets send data out of order, so, some packets might need reprocessing

def start_processing_ip_payloads(sleep_time = 0.5):
	"""Starts the IP payload processor as threaded"""
	processing_thread = threading.Thread(target = process_ip_payloads, name = "IP payload processor", args = (sleep_time,))
	processing_thread.daemon = True
	processing_thread.start()