import socket, sys, gc, time

BYTEORDER = sys.byteorder
SERVER_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
UPSTREAM_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
UPSTREAM_IP = "1.1.1.1"
UPSTREAM_PORT = 53
CACHED_A = {}
CACHED_AAAA = {}
BLOCKLIST_FILE = "blocklist.txt"


def binarySearch(item, data):
	print(item, data)
	front = 0
	rear = len(data)-1
	found = False

	while front <= rear:
		mid = (front + rear) // 2

		if data[mid] == item :
			return True

		else:
			if item < data[mid]:
				rear = mid - 1
			else:
				front = mid + 1

	return False


def upstreamQuery(data):    #sends data parameter to upstream IP and returns result
	result = None
	timeout = time.time() + 0.2
	UPSTREAM_SOCKET.sendto(data, (UPSTREAM_IP, UPSTREAM_PORT))

	while result == None:
		try:
			if time.time() >= timeout:
				print("Timeout, resending query...")
				UPSTREAM_SOCKET.sendto(data, (UPSTREAM_IP, UPSTREAM_PORT))
				timeout = time.time() + 0.2

			result = UPSTREAM_SOCKET.recvfrom(1024)[0]

		except OSError:
			pass

	return result


def denyQuery(id, qname, qtype):
	return id + b"\\x81\\x80\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00" \
	+ qname + qtype


def checkResponse(data):
	if data[7] == 1:
		return True
	else:
		return False


def returnResult(id, qname, qtype, data):    #selects whether query is A or AAAA, constructs packet to return
	if qtype == b"\x00\x01":
		print("Resolving IPV4 (A) query...")
		record = CACHED_A.get(qname)

		if record != None:
			print("Using cached value...")
			rdlendata = b"\x00\x04" + record

		else:
			print("Querying upstream server...")
			upstreamData = upstreamQuery(data)

			if checkResponse(upstreamData):
				rddata = upstreamData[-4:]
				CACHED_A[qname] = rddata
				rdlendata = b"\x00\x04" + rddata

			else:
				return upstreamData

	elif qtype == b"\x00\x1c":
		print("Resolving IPV6 (AAAA) query...")
		record = CACHED_AAAA.get(qname)

		if record != None:
			print("Using cached value...")
			rdlendata = b"\x00\x10" + record

		else:
			print("Querying upstream server...")
			upstreamData = upstreamQuery(data)

			if checkResponse(upstreamData):
				rddata = upstreamData[-16:]
				CACHED_AAAA[qname] = rddata
				rdlendata = b"\x00\x10" + rddata

			else:
				return upstreamData

	ttl = b"\x00\xd7"

	packet = id + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + qname \
	+ qtype + b"\x00\x01\xc0\x0c" + qtype + b"\x00\x01\x00\x00" + ttl + rdlendata

	return packet


def main():
	print("Starting...\nSystem byteorder: %s\nUpstream DNS server: %s" % (BYTEORDER, UPSTREAM_IP))

	UPSTREAM_SOCKET.setblocking(0)
	SERVER_SOCKET.bind(("", 53))

	with open(BLOCKLIST_FILE) as blocklist:
		BLOCKLIST = [line.encode("ascii") for line in blocklist.read().split(" ")]

	flushTime = time.time() + 3600

	try:
		while True:
			data, client = SERVER_SOCKET.recvfrom(1024)
			print("\n---------------------\nClient: %s\n" % (client[0]))

			if data[3] != 0:
				id = qname = qtype = None
			else:
				id = data[:2]
				qname = data[12:][:-4]
				qtype = data[-4:][:-2]

			if binarySearch(qname, BLOCKLIST):
				print("Domain blocked...")
				SERVER_SOCKET.sendto(denyQuery(id, qname, qtype), client)
				continue

			if (id == None and qname == None and qtype == None) or (qtype != b"\x00\x01" and qtype != b"\x00\x1c"):
				print("Sending upstream...")
				SERVER_SOCKET.sendto(upstreamQuery(data), client)

			else:
				SERVER_SOCKET.sendto(returnResult(id, qname, qtype, data), client)

			freeMemory = gc.mem_free()
			print(freeMemory, "bytes free")
			currentTime = time.time()

			if (currentTime > flushTime) or (freeMemory < 5000):
				gc.collect()
				CACHED_A.clear()
				CACHED_AAAA.clear()
				flushTime = currentTime + 3600
				print("\x1bc")
				print("Cache flushed at", currentTime)

	except KeyboardInterrupt:
		print("\nStopping")
		SERVER_SOCKET.close()
		UPSTREAM_SOCKET.close()


main()
