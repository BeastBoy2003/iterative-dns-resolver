import socket
from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE

ROOT_SERVERS = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33"
]
DNS_PORT = 53
SOCKET_TIMEOUT = 2
MAX_CNAME_CHAIN = 10

cache = {}  # domain -> {'A': [ip], 'NS': [ip], 'source': 'cache/server'}

def get_dns_record(udp_socket, domain: str, parent_server: str, record_type):
    q = DNSRecord.question(domain, qtype=record_type)
    q.header.rd = 0  # iterative query
    udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))
    try:
        pkt, _ = udp_socket.recvfrom(8192)
    except socket.timeout:
        print(f"[Timeout] No response from {parent_server}")
        return None

    buff = DNSBuffer(pkt)
    header = DNSHeader.parse(buff)
    if header.rcode != RCODE.NOERROR:
        return None

    for _ in range(header.q):
        DNSQuestion.parse(buff)
    answers, auth, additional = [], [], []
    for _ in range(header.a):
        answers.append(RR.parse(buff))
    for _ in range(header.auth):
        auth.append(RR.parse(buff))
    for _ in range(header.ar):
        additional.append(RR.parse(buff))
    return answers, auth, additional

def print_cache():
    if not cache:
        print("Cache is empty")
        return
    for idx, (domain, data) in enumerate(cache.items(), start=1):
        print(f"{idx}. {domain} -> {data}")

def remove_cache(index):
    if index < 1 or index > len(cache):
        print("Invalid index")
        return
    key = list(cache.keys())[index - 1]
    del cache[key]
    print(f"Removed cache entry {index}: {key}")

def get_ns_ips(sock, ns_records):
    ips = []
    for ns in ns_records:
        if ns.rtype == QTYPE.NS:
            ns_name = str(ns.rdata)
            if ns_name in cache and 'A' in cache[ns_name]:
                ips.append(cache[ns_name]['A'][0])
            else:
                ip = resolve_domain(sock, ns_name)
                if ip:
                    ips.append(ip)
    return ips

def resolve_domain(sock, domain):
    queried_servers = set()
    current_domain = domain
    cname_chain = 0
    current_servers = ROOT_SERVERS.copy()

    while current_servers and cname_chain < MAX_CNAME_CHAIN:
        next_servers = []
        resolved_ip = None

        # Check cache
        if current_domain in cache and 'A' in cache[current_domain]:
            print(f"[Cache] IP for {current_domain}: {cache[current_domain]['A']}")
            return cache[current_domain]['A'][0]

        for server in current_servers:
            if server in queried_servers:
                continue
            queried_servers.add(server)
            result = get_dns_record(sock, current_domain, server, "A")
            if result is None:
                continue
            answers, auth, additional = result

            # Check Answers
            for ans in answers:
                if ans.rtype == QTYPE.A:
                    resolved_ip = str(ans.rdata)
                    cache[current_domain] = {'A': [resolved_ip], 'source': server}
                    print(f"[Resolved] {current_domain} -> {resolved_ip} (from {server})")
                    break
                elif ans.rtype == QTYPE.CNAME:
                    current_domain = str(ans.rdata)
                    cname_chain += 1
                    print(f"[CNAME] Redirect to {current_domain}")
                    break
            if resolved_ip or cname_chain > 0:
                break

            # Additional section for next servers
            for adr in additional:
                if adr.rtype == QTYPE.A:
                    next_servers.append(str(adr.rdata))

            # Authority section if additional doesn't have IPs
            if not next_servers and auth:
                next_servers = get_ns_ips(sock, auth)

        if resolved_ip:
            return resolved_ip
        if not next_servers:
            print(f"[Failed] Could not resolve {domain}")
            return None
        current_servers = next_servers

    if cname_chain >= MAX_CNAME_CHAIN:
        print(f"[Error] Too many CNAME redirects for {domain}")
        return None

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(SOCKET_TIMEOUT)

    while True:
        user_input = input("Enter domain or command > ").strip()
        if user_input == ".exit":
            break
        elif user_input == ".list":
            print_cache()
        elif user_input == ".clear":
            cache.clear()
            print("Cache cleared")
        elif user_input.startswith(".remove"):
            parts = user_input.split()
            if len(parts) != 2 or not parts[1].isdigit():
                print("Usage: .remove N")
                continue
            remove_cache(int(parts[1]))
        else:
            resolve_domain(sock, user_input)

    sock.close()

if __name__ == "__main__":
    main()
if __name__ == "__main__":
    main()
