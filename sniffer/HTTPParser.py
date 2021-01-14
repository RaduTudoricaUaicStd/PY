import gzip
import deflate
import threading
import time
import queue

from .TCPLayer import NEW_SOCK_QUEUE

HTTP_REQUEST_RESPONSE_QUEUE = queue.Queue()
HTTP_PARSER_SHUTDOWN_EVENT = threading.Event()

class HTTPRequest(object):
	"""An object to hold the parsed data from an HTTP request"""
	def __init__(self, method, request_targhet, http_type, url_arguments, request_data, body, headers):
		self.method = method
		self.request_targhet = request_targhet
		self.http_type = http_type
		self.url_arguments = url_arguments
		self.request_data = request_data
		self.body = body
		self.headers = headers

class HTTPResponse(object):
	"""An object to hold the parsed data from an HTTP response"""
	def __init__(self, http_type, code, code_message, body, headers):
		self.http_type = http_type
		self.code = code
		self.code_message = code_message
		self.body = body
		self.headers = headers



class HTTPParser(object):
	"""Parser for requests and responses"""
	def __init__(self, src, dst):
		self.src = src
		self.dst = dst

	def parse_request(self):
		"""Parse an upcomming request, return None if it is't an HTTP request"""
		first_line = self.src.recv_until(b"\r\n")
		if b"HTTP/1" in first_line:
			return self.parse_http1_request(first_line)
		return None

	def parse_response(self):
		"""Parse an upcomming response, return None if it is't an HTTP response"""
		first_line = self.dst.recv_until(b"\r\n")
		if b"HTTP/1" in first_line:
			return self.parse_http1_response(first_line)
		return None

	def parse_http1_headers(self, tsock):
		"""Parse HTTP headers"""
		parsed_headers = {}
		headers = tsock.recv_until(b"\r\n\r\n").strip()
		for assignment in headers.split(b"\r\n"):
			if not b": " in assignment:
				continue
			variable, value = assignment.split(b": ", 1)
			parsed_headers[variable] = value
		return parsed_headers

	def read_body_http1(self, tsock, headers):
		"""Read HTTP body and decode the body"""
		if not b"Content-Length" in headers and not b"Transfer-Encoding" in headers:
			return None
		transfer_encoding = "identity"
		if b"Transfer-Encoding" in headers:
			if headers[b"Transfer-Encoding"] == b"chunked":
				transfer_encoding = "chunked"
		if transfer_encoding == "identity":
			if not b"Content-Length" in headers:
				return None
			body_size = int(headers[b"Content-Length"].decode("utf-8"))
			return self.body_content_decode_http1(tsock.recv(body_size), headers)
		else:
			body = b""
			chunk_size = int(tsock.recv_until(b"\r\n")[:-2].decode("utf-8"), 16)
			while chunk_size > 0:
				body += tsock.recv(chunk_size)
				tsock.recv(2)
				chunk_size = int(tsock.recv_until(b"\r\n")[:-2].decode("utf-8"), 16)
			tsock.recv(2)
			return self.body_content_decode_http1(body, headers)

	def body_content_decode_http1(self, body, headers):
		"""Decode the HTTP body"""
		if not b"Content-Encoding" in headers:
			return body
		for encoding in headers[b"Content-Encoding"].split(b", ")[::-1]:
			if encoding == b"identity":
				continue
			elif encoding == b"gzip":
				body = gzip.decompress(body)
			elif encoding == b"deflate":
				body = deflate.gzip_decompress(body)
		return body

	def parse_http1_response(self, first_line):
		"""Parse HTTP1.x response"""
		http_type, code, code_message = first_line.strip().split(b" ", 2)
		headers = self.parse_http1_headers(self.dst)
		body = self.read_body_http1(self.dst, headers)
		return HTTPResponse(http_type, code, code_message, body, headers)

	def parse_http1_request(self, first_line):
		"""Parse HTTP1.x request"""
		method, request_targhet, http_type = first_line.strip().split(b" ", 2)
		url_arguments = None
		request_data = None
		if b"?" in request_targhet:
			request_data = request_targhet[request_targhet.index(b"?")+1:]
			if b"=" in request_data:
				url_arguments = {}
				for assignment in request_data.split(b"&"):
					if not b"=" in assignment:
						continue
					variable, value = assignment.split(b"=", 1)
					url_arguments[variable] = value
		headers = self.parse_http1_headers(self.src)
		body = self.read_body_http1(self.src, headers)
		return HTTPRequest(method, request_targhet, http_type, url_arguments, request_data, body, headers)

def produce_parsed_http_traffic(src, dst):
	parser = HTTPParser(src, dst)
	while not src.is_closed() and not dst.is_closed() and not HTTP_PARSER_SHUTDOWN_EVENT.is_set():
		request = parser.parse_request()
		if request is None:
			break
		response = parser.parse_response()
		if response is None:
			break
		HTTP_REQUEST_RESPONSE_QUEUE.put(((src.src_ip, src.src_port), (dst.src_ip, dst.src_port), request, response))

def start_producers():
	while not HTTP_PARSER_SHUTDOWN_EVENT.is_set():
		src, dst = NEW_SOCK_QUEUE.get()
		t = threading.Thread(target = produce_parsed_http_traffic, args = (src, dst))
		t.daemon = True
		t.start()

def run_start_producers_thread():
	t = threading.Thread(target = start_producers, args = tuple())
	t.daemon = True
	t.start()	