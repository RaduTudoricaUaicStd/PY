import re
import socket
import time
import argparse

from sniffer import PacketProducer, IPLayer, TCPLayer, HTTPParser

request_filters = {
	"method": lambda x: True,
	"headers": lambda x: True,
	"body": lambda x: True,
}

response_filters = {
	"code": lambda x: True,
	"headers": lambda x: True,
	"body": lambda x: True,
}

source_filter = lambda x: True
destination_filter = lambda x: True

request_print_template = """============================= <REQUEST> =============================

----------------------------- <METHOD> ------------------------------

%method%

----------------------------- </METHOD> -----------------------------

----------------------------- <HEADERS> -----------------------------

%headers%

----------------------------- </HEADERS> ----------------------------

----------------------------- <PAYLOAD> -----------------------------

%payload%

----------------------------- </PAYLOAD> ----------------------------

============================= </REQUEST> ============================
"""

response_print_template = """============================= <RESPONSE> ============================

-----------------------------  <CODE> -------------------------------

%code%

-----------------------------  </CODE> ------------------------------

----------------------------- <HEADERS> -----------------------------

%headers%

----------------------------- </HEADERS> ----------------------------

----------------------------- <PAYLOAD> -----------------------------

%payload%

----------------------------- </PAYLOAD> ----------------------------

============================= </RESPONSE> ===========================
"""

packets = []

def start_sniffing():
	PacketProducer.sniff_on_interface_list(PacketProducer.list_local_ips(filter_function = lambda interface: socket.AF_INET in interface))
	IPLayer.start_processing_raw_packets()
	TCPLayer.start_processing_ip_payloads()
	HTTPParser.run_start_producers_thread()

def stop_sniffing():
	PacketProducer.PACKET_PRODUCER_SHUTDOWN_EVENT.set()
	IPLayer.IP_PRODUCER_SHUTDOWN_EVENT.set()
	TCPLayer.TCP_PRODUCER_SHUTDOWN_EVENT.set()
	HTTPParser.HTTP_PARSER_SHUTDOWN_EVENT.set()

def apply_filter_on_headers(filter, headers):
	for key, value in headers.items():
		if filter(key+b": "+value):
			return True
	return False

def filter_request(request):
	return request_filters["method"](request.method) and apply_filter_on_headers(request_filters["headers"], request.headers) and request_filters["body"](request.body)

def filter_response(response):
	return response_filters["code"](response.code) and apply_filter_on_headers(response_filters["headers"], response.headers) and response_filters["body"](response.body)

def format_headers(headers):
	formated_headers = ""
	for header, value in headers.items():
		formated_headers += (header+b": "+value).decode('utf-8')+"\n"
	return formated_headers

def pretty_print_packet(packet):
	request, response = packet
	print(request_print_template.replace("%method%", request.method.decode('utf-8')).replace("%headers%", format_headers(request.headers)).replace("%payload%", repr(request.body)))
	print(response_print_template.replace("%code%", response.code.decode('utf-8')+" "+response.code_message.decode("utf-8")).replace("%headers%", format_headers(response.headers)).replace("%payload%", repr(response.body)))

def process_requests_and_responses():
	try:
		while True:
			if HTTPParser.HTTP_REQUEST_RESPONSE_QUEUE.empty():
				time.sleep(0.1)
				continue
			source, destination, request, response = HTTPParser.HTTP_REQUEST_RESPONSE_QUEUE.get()
			if source_filter(source[0]) and destination_filter(destination[0]) and filter_request(request) and filter_response(response):
				print("ID:", len(packets))
				print("Request", request.method.decode("utf-8"),"from", source[0]+":"+str(source[1]), "to", destination[0]+":"+str(destination[1]))
				print("Response with code", response.code.decode("utf-8"), "from", destination[0]+":"+str(destination[1]), "to", source[0]+":"+str(source[1]))
				print()
				packets.append((request, response))
	except KeyboardInterrupt:
		try:
			ids = list(map(lambda id: int(id.strip()), input("Select the ids for deailed view (comma separated): ").split(",")))
			for id in ids:
				pretty_print_packet(packets[id])
		except:
			return


if __name__ == "__main__":
	arg_parser = argparse.ArgumentParser(description='Sniff HTTP traffic.')
	arg_parser.add_argument('--request-method-filter', help='Regex to filter request method')
	arg_parser.add_argument('--request-header-filter', help='Regex to filter request headers')
	arg_parser.add_argument('--request-body-filter', help='Regex to filter request body')
	arg_parser.add_argument('--response-code-filter', help='Regex to filter response code')
	arg_parser.add_argument('--response-header-filter', help='Regex to filter response headers')
	arg_parser.add_argument('--response-body-filter', help='Regex to filter response body')
	arg_parser.add_argument('--source-filter', help='Regex to filter the source')
	arg_parser.add_argument('--destination-filter', help='Regex to filter the destination')
	args = arg_parser.parse_args()
	
	if not args.request_method_filter is None:
		request_filters["method"] = lambda x: len(re.findall(args.request_method_filter.encode('utf-8'), x)) > 0

	if not args.request_header_filter is None:
		request_filters["headers"] = lambda x: len(re.findall(args.request_header_filter.encode('utf-8'), x)) > 0

	if not args.request_body_filter is None:
		request_filters["body"] = lambda x: len(re.findall(args.request_body_filter.encode('utf-8'), x)) > 0

	if not args.response_code_filter is None:
		response_filters["code"] = lambda x: len(re.findall(args.response_code_filter.encode('utf-8'), x)) > 0

	if not args.response_header_filter is None:
		response_filters["headers"] = lambda x: len(re.findall(args.response_header_filter.encode('utf-8'), x)) > 0

	if not args.response_body_filter is None:
		response_filters["body"] = lambda x: len(re.findall(args.response_body_filter.encode('utf-8'), x)) > 0

	if not args.source_filter is None:
		source_filter = lambda x: len(re.findall(args.source_filter, x)) > 0

	if not args.destination_filter is None:
		destination_filter = lambda x: len(re.findall(args.destination_filter, x)) > 0

	start_sniffing()
	process_requests_and_responses()
	stop_sniffing()