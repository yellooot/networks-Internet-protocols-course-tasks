import socket
from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RCODE, A, DNSError

ROOT_SERVER_IP = '192.5.5.241'
BUFFER_SIZE = 1024
MAX_REQUEST_AMOUNT = 129


def get_dns_reply_from_answer_section(query_name: str, answer_section: list, query_id: int,
                                      was_nxdomain: bool) -> bytes:
    header = DNSHeader(id=query_id, qr=1, aa=0, ra=1)
    if was_nxdomain:
        header = DNSHeader(id=query_id, qr=1, aa=0, ra=1, rcode=RCODE.NXDOMAIN)

    dns_response = DNSRecord(header=header, rr=answer_section)
    dns_response.add_question(DNSQuestion(qname=query_name, qtype=QTYPE.A))
    return dns_response.pack()


def get_dns_single_query_data(query_name: str, query_id: int) -> bytes:
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_query = DNSRecord.question(query_name)
    query_bytes = dns_query.pack()

    try:
        answer_section = []
        was_nxdomain = False
        current_ip = ROOT_SERVER_IP
        request_index = 0
        while request_index < MAX_REQUEST_AMOUNT:
            udp_socket.sendto(query_bytes, (current_ip, 53))
            response, _ = udp_socket.recvfrom(BUFFER_SIZE)
            dns_response = DNSRecord.parse(response)
            if dns_response.header.rcode == 3:
                was_nxdomain = True
                break
            answer_section = dns_response.rr
            if len(answer_section) > 0:
                break
            for ip_data in dns_response.ar:
                if isinstance(ip_data.rdata, A):
                    current_ip = repr(ip_data.rdata)
                    break

            request_index += 1
        return get_dns_reply_from_answer_section(query_name, answer_section, query_id, was_nxdomain)
    finally:
        udp_socket.close()


def handle_dns_request(data: bytes, addr: str, sock: socket.socket) -> None:
    try:
        dns_request = DNSRecord.parse(data)
        for question in dns_request.questions:
            if question.qtype == 1:
                dns_response = get_dns_single_query_data(question.qname, dns_request.header.id)
                sock.sendto(dns_response, addr)
    except DNSError:
        sock.sendto(get_dns_reply_from_answer_section('', [], 0, True), addr)


def main() -> None:
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(('127.0.0.1', 53))  # run with sudo in terminal
    try:
        while True:
            data, addr = udp_socket.recvfrom(BUFFER_SIZE)
            handle_dns_request(data, addr, udp_socket)
    finally:
        udp_socket.close()


if __name__ == "__main__":
    main()
