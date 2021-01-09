import socket
import netifaces
import threading
import queue

RAW_PACKET_QUEUE = queue.Queue()                    #The queue that receives all the packets.
PACKET_PRODUCER_SHUTDOWN_EVENT = threading.Event()  #The shutdown event for all producer threads
IP_TYPE_TO_COMMON_NAME = {							#Used in other functions for not repeating the same lines of code:
	socket.AF_INET: "IPv4",							#if ipv4: do_thing()
	socket.AF_INET6: "IPv6"							#else: do_other_ting()
}

def sniff_on_interface(ip, ip_type):
	"""
		Sniff incomming and outgoing packets where the specified ip is either the source or the destination.
		Each packet will be put in RAW_PACKET_QUEUE.

	"""
	try:
		if ip_type == socket.AF_INET:
			raw_socket = socket.socket(ip_type, socket.SOCK_RAW, socket.IPPROTO_IP)
		else:
			print("[!!!] Only IPv4 interfaces are supported (for now)")
			return
		raw_socket.bind((ip, 0))
		raw_socket.ioctl(socket.SIO_RCVALL, 1) #winapi magic; enables receiving all packets on the interface (in theory, anyway https://docs.microsoft.com/en-us/windows/win32/winsock/sio-rcvall)
	except Exception as e:
		print("[!!!] Cannot start sniffing on", ip, e)
		return

	while not PACKET_PRODUCER_SHUTDOWN_EVENT.is_set():
		packet, ip_info = raw_socket.recvfrom(65535)
		RAW_PACKET_QUEUE.put((packet, ip_info, ip_type))

def list_local_ips(filter_function = lambda interface: True):
	"""Returns a list of interfaces that the computer has (physical and virtual).
	   The filter_function argument can be used to filter interfaces by any criteria.
	"""
	ips = []
	for interface in filter(filter_function, map(netifaces.ifaddresses, netifaces.interfaces())):
		for ip_type in [socket.AF_INET, socket.AF_INET6]:
			if ip_type in interface:
				for ip_info in interface[ip_type]:
					ips.append((ip_info["addr"], ip_type))
	return ips

def sniff_on_interface_list(interface_list):
	"""Starts sniffing on a list of interfaces of format [(ip, ip_type), ...]"""
	for ip, ip_type in interface_list:
		sniffing_thread = threading.Thread(target = sniff_on_interface, name = "Sniffer on "+ip, args = (ip, ip_type))
		sniffing_thread.daemon = True
		sniffing_thread.start()