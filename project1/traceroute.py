import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        self.version = buffer[0] >> 4
        tmp = buffer[0] % 16
        self.header_len = tmp * 4
        self.tos = buffer[1]
        self.length = int.from_bytes(buffer[2:4], byteorder='big')
        self.id = int.from_bytes(buffer[4:6], byteorder='big')
        
        flags_and_offset = int.from_bytes(buffer[6:8], byteorder='big')
        self.flags = (flags_and_offset // (2 ** 13)) % 8
        self.frag_offset = flags_and_offset % (2 ** 13)
        
        self.ttl = buffer[8]
        self.proto = buffer[9]
        self.cksum = int.from_bytes(buffer[10:12], byteorder='big')
        self.src = util.inet_ntoa(buffer[12:16])
        self.dst = util.inet_ntoa(buffer[16:20])

    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        self.type = buffer[0]
        self.code = buffer[1]
        self.cksum = int.from_bytes(buffer[2:4], byteorder='big')

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        self.src_port = int.from_bytes(buffer[0:2], byteorder='big')
        self.dst_port = int.from_bytes(buffer[2:4], byteorder='big')
        self.len = int.from_bytes(buffer[4:6], byteorder='big')
        self.cksum = int.from_bytes(buffer[6:8], byteorder='big')

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like

# Test B2-B5
def test_1(buf, ipv4: IPv4):
    # process ICMP proto
    # B4
    if ipv4.proto == 1:
        icmp_header_idx = ipv4.header_len
        icmp_header = buf[icmp_header_idx:]
        # B5
        if len(icmp_header) < 4:
            return True
        icmp = ICMP(icmp_header)
        # B2
        if icmp.type == 3:
            return False
        elif icmp.type == 11:
            # B3
            if icmp.code != 0:
                return True
            else:
                return False
        else:
            return True
    return True

# Test B6
def test_2(buf):
    if len(buf) < 20:
        return True
    else:
        ipv4 = IPv4(buf)
        if len(buf) < ipv4.length:
            return True
        if ipv4.proto == 1:
            icmp_header_idx = ipv4.header_len
            icmp_header = buf[icmp_header_idx:]
            if len(icmp_header) < 4:
                return True
        elif ipv4.proto == 17:
            udp_header_idx = ipv4.header_len
            udp_header = buf[udp_header_idx:]
            if len(udp_header) < 8:
                return True
        else:
            return False
        
        

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    # TODO Add your implementation
    results = []
    debug_res = []
    idx = -1
    last_ip = ""
    
    sent_msg_num = 0
    
    ttl = 1
    while ttl <= TRACEROUTE_MAX_TTL:
        sendsock.set_ttl(ttl)
        routers = []

        for i in range(PROBE_ATTEMPT_COUNT):
            sent_msg_num += 1
            msg = f"This is my {i}th attempt to send POTATO with {ttl}!".encode()
            sendsock.sendto(msg, (ip, TRACEROUTE_PORT_NUMBER))

            if recvsock.recv_select():
                buf, _ = recvsock.recvfrom()
                
                # Test B6
                if test_2(buf):
                    continue
                
                ipv4 = IPv4(buf)
                
                # Test B2-B5
                if test_1(buf, ipv4):
                    continue
                
                ip_src = ipv4.src
                
                routers.append(ip_src)

                if ip_src == ip:
                    results.append(list(set(routers)))
                    debug_res.append(routers)
                    idx += 1
                    util.print_result(results[idx], ttl)
                    # raise ValueError(f'debug_res = {debug_res} and \ndebug_msg = {debug_msg}')
                    return results
                
        # Test B13-B14
        if len(list(set(routers))) > 0:
            if last_ip != "":
                if len(list(set(routers))) == 1:
                    new_ip = list(set(routers))[0]
                    if last_ip == new_ip:
                        continue
                    
            last_ip = list(set(routers))[-1]

        results.append(list(set(routers)))
        debug_res.append(routers)
        idx += 1
        util.print_result(results[idx], ttl)
        
        ttl += 1

    return results


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    # traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
    
    sendsock = util.Socket.make_udp()
    recvsock = util.Socket.make_icmp()
    
    sendsock.set_ttl(12)
    message = f"Potato{34:05d}".encode()
    sendsock.sendto(message, (ip_addr, TRACEROUTE_PORT_NUMBER))
    
    if recvsock.recv_select():  # Check if there's a packet to process.
        buf, address = recvsock.recvfrom()  # Receive the packet.

        # Print out the packet for debugging.
        last_buf = str(buf)[-6:-1]
        print(f'last buf is {last_buf} and if the last_buf the string: {type(last_buf)}, and buf {type(buf)}')
        print(f"Packet bytes: {buf.hex()}")
        print(f"Packet is from IP: {address[0]}")
        print(f"Packet is from port: {address[1]}")
    