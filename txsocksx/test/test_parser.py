import struct
import parsley

from unittest import TestCase

from txsocksx.parser import SOCKSGrammar

# From https://gist.github.com/1595135
def IPV4StrToInt(s):
    """
    Returns the 32 bits representing an IP address from a string.
    """
    return reduce(lambda a,b: a<<8 | b, map(int, s.split(".")))

dummyDomain = 'example.com'
dummyIPV4Addr = '127.0.0.1'
dummyIPV4AddrBytes = struct.pack('!i', IPV4StrToInt(dummyIPV4Addr))

dummyPort = 1080
dummyPortBytes = struct.pack('l', dummyPort)

dummyClientVersionMethodMessageNoAuthV5 = \
    '\x05\x01\x00'

dummyServerVersionMethodMessageNoAuthV5 = \
    '\x05\x00'

dummySOCKSAddrIPV4 = '\x01' + dummyIPV4AddrBytes
dummySOCKSAddrDomain = '\x04' + '\x08' + dummyDomain

dummyClientRequestMessageConnectDomainV5 = \
        '\x05\x01\x00' + dummySOCKSAddrDomain

dummyServerReplyMessageSuccessIPV4 = \
        '\x05\x00\x00' + '\x03' + dummyIPV4AddrBytes + dummyPortBytes


class TestSOCKSParser(TestCase):
    def test_parse_socks_domain(self):
        p = SOCKSGrammar(dummySOCKSAddrDomain)
        self.assertEqual(p.SOCKSAddress(),
                'example.com')

    def test_parse_socks_ipv4(self):
        p = SOCKSGrammar(dummySOCKSAddrIPV4)
        self.assertEqual(p.SOCKSAddress(),
                '127.0.0.1')

    def test_parse_client_connect_request_message(self):
        p = SOCKSGrammar(dummyClientRequestMessageConnectDomainV5)
        self.assertEqual(p.clientRequestMessage(),
                    ('Connect', dummyIPV4Addr, dummyPort))

    def test_parse_client_request_message(self):
        p = SOCKSGrammar(dummyServerReplyMessageSuccessIPV4)
        self.assertEqual(p.clientRequestMessage(),
                ('Success', dummyIPV4Addr, dummyPort))


