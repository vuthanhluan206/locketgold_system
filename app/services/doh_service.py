"""
Controlled Research Lab DNS-over-HTTPS (RFC 8484 Wireformat & JSON) Resolver Service (`app/services/doh_service.py`).
Strictly scoped to domains in `settings.lab_scoped_domains` (controlled by the researcher).
Never resolves or intercepts third-party payment or external production domains, and never acts as an open recursive DNS proxy.
"""
import base64
import ipaddress
import struct

TYPE_A = 1
TYPE_AAAA = 28
CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5


def build_dns_query_packet(qname: str, qtype: int = TYPE_A, txid: int = 0x1234) -> bytes:
    """Build a standard RFC 1035 DNS query packet in wireformat for testing RFC 8484 DoH."""
    header = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    labels = b''
    for part in qname.strip('.').split('.'):
        encoded = part.encode('ascii')
        labels += struct.pack('!B', len(encoded)) + encoded
    labels += b'\x00'
    question = labels + struct.pack('!HH', qtype, CLASS_IN)
    return header + question


def parse_dns_question(packet: bytes) -> tuple[int, int, str, int, int, int]:
    """
    Parse an RFC 1035 DNS query packet.
    Returns `(txid, flags, qname, qtype, qclass, question_end_offset)`.
    Raises `ValueError` on malformed packets.
    """
    if not isinstance(packet, (bytes, bytearray)) or len(packet) < 17 or len(packet) > 512:
        raise ValueError('Invalid DNS packet size')
    txid, flags, qdcount, _, _, _ = struct.unpack('!HHHHHH', packet[:12])
    if qdcount < 1:
        raise ValueError('DNS query contains no question section')
    offset = 12
    labels = []
    while offset < len(packet):
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(packet):
            raise ValueError('Invalid DNS label length')
        labels.append(packet[offset: offset + length].decode('ascii', errors='strict').lower())
        offset += length
    else:
        raise ValueError('Unterminated DNS qname')

    if offset + 4 > len(packet):
        raise ValueError('Truncated DNS question section')
    qtype, qclass = struct.unpack('!HH', packet[offset: offset + 4])
    offset += 4
    qname = '.'.join(labels)
    return txid, flags, qname, qtype, qclass, offset


def resolve_lab_dns_wireformat(
    packet: bytes,
    *,
    allowed_domains: list[str],
    target_ipv4: str = '127.0.0.1',
    target_ipv6: str = '',
    ttl: int = 60,
) -> tuple[bytes, dict]:
    """
    Resolve an RFC 8484 DNS wireformat query strictly for domains in `allowed_domains`.
    - If `qname` is in `allowed_domains` and `qtype == TYPE_A (1)`, returns `NOERROR` with the configured `target_ipv4`.
    - If `qname` is in `allowed_domains` and `qtype == TYPE_AAAA (28)`:
      - When `target_ipv6` is configured, returns `NOERROR` with the 16-byte AAAA record.
      - When `target_ipv6` is empty, returns `NOERROR` with 0 answers (`NOERROR_NODATA`) so dual-stack iOS clients
        cleanly fall back to the IPv4 Lab listener rather than failing or bypassing via IPv6.
    - If `qname` is NOT in `allowed_domains`, returns `REFUSED` (rcode=5) so the endpoint never operates as an open resolver.
    """
    txid, req_flags, qname, qtype, qclass, q_end = parse_dns_question(packet)
    question_bytes = bytes(packet[12:q_end])
    allowed_set = {d.strip().lower().rstrip('.') for d in allowed_domains if d.strip()}
    rd_bit = req_flags & 0x0100

    if qname not in allowed_set:
        # REFUSED (rcode=5), QR=1, RA=0 (not an open recursive resolver)
        resp_flags = 0x8000 | rd_bit | RCODE_REFUSED
        header = struct.pack('!HHHHHH', txid, resp_flags, 1, 0, 0, 0)
        return header + question_bytes, {
            'qname': qname,
            'qtype': qtype,
            'rcode': 'REFUSED',
            'answer_ip': None,
        }

    if qtype == TYPE_A and qclass == CLASS_IN:
        ip_bytes = ipaddress.IPv4Address(target_ipv4).packed
        # QR=1, AA=1 (Authoritative for Lab domain), RD preserved, RA=1, RCODE=0
        resp_flags = 0x8480 | rd_bit | RCODE_NOERROR
        header = struct.pack('!HHHHHH', txid, resp_flags, 1, 1, 0, 0)
        # Name pointer to offset 12 (0xC00C), Type A, Class IN, TTL, RDLENGTH=4, RDATA
        answer = struct.pack('!HHHLH', 0xC00C, TYPE_A, CLASS_IN, ttl, 4) + ip_bytes
        return header + question_bytes + answer, {
            'qname': qname,
            'qtype': qtype,
            'rcode': 'NOERROR',
            'answer_ip': target_ipv4,
        }

    if qtype == TYPE_AAAA and qclass == CLASS_IN and target_ipv6.strip():
        ip6_bytes = ipaddress.IPv6Address(target_ipv6.strip()).packed
        resp_flags = 0x8480 | rd_bit | RCODE_NOERROR
        header = struct.pack('!HHHHHH', txid, resp_flags, 1, 1, 0, 0)
        answer = struct.pack('!HHHLH', 0xC00C, TYPE_AAAA, CLASS_IN, ttl, 16) + ip6_bytes
        return header + question_bytes + answer, {
            'qname': qname,
            'qtype': qtype,
            'rcode': 'NOERROR',
            'answer_ip': target_ipv6.strip(),
        }

    # Authoritative NODATA (0 answers) for AAAA (when IPv6 not configured) / SVCB / HTTPS on lab-scoped domains
    resp_flags = 0x8480 | rd_bit | RCODE_NOERROR
    header = struct.pack('!HHHHHH', txid, resp_flags, 1, 0, 0, 0)
    return header + question_bytes, {
        'qname': qname,
        'qtype': qtype,
        'rcode': 'NOERROR_NODATA',
        'answer_ip': None,
    }


def decode_base64url_dns_param(dns_param: str) -> bytes:
    clean = dns_param.strip()
    padding = '=' * (-len(clean) % 4)
    return base64.urlsafe_b64decode(clean + padding)
