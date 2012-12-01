import parsley
import struct

socks_grammar = """
# XXX Is this correct?
octet = anything

byteToInt = octet:b
    -> ord(b)

byteToIntStr = octet:b
    -> str(ord(b))

ver = '\x05' | '\x04'

rsv = '\x00'

IPV4Addr = anything{4}:quads
    -> '.'.join(str(ord(q)) for q in quads)

IPV6Addr = <anything{16}>

# XXX notes
# letterOrDigitOrHyphen = letterOrDigit | '-'
# domainLabel = <(letter letterOrDigitOrHyphen{0, 61} letterOrDigit)>
# domainName =
#    < (domainLabel '.'?)* >

# XXX make this stricter
SOCKSDomainName =
    byteToInt:len <anything*>

SOCKSAddress = (token('\x01') IPV4Addr:addr
                    -> addr

                | token('\x03') IPV6Addr:addr
                    -> addr

                | token('\x04') SOCKSDomainName:domain
                    -> domain
                )

port = anything{2}

# The Client version identified/method selection message
clientVersionMethodMessage =
    ver octet:nmethods octet{1, 255}:methods
    -> (ver, nmethods, methods)

methods = tokenize('\x00') -> 'No Authentication Required'
          | tokenize('\x01') -> 'GSSAPI'
          | tokenize('\x02') -> 'Username/Password'
          | tokenize('\xFF') -> 'No Acceptable Methods'

# The Server version identified/method selection message
serverVersionMethodMessage =
    ver methods -> (ver, method)

cmd = token('\x01') -> 'Connect'
      | token('\x02') -> 'Bind'
      | token('\x03') -> 'UDP Associate'

clientRequestMessage =
    ver cmd rsv SOCKSAddress port

rep = token('\x00') -> 'Suceeded'
      | token('\x01') -> 'General SOCKS server failure'
      | token('\x02') -> 'Connection not allowed'
      | token('\x03') -> 'Network unreachable'
      | token('\x04') -> 'Host unreachable'
      | token('\x05') -> 'Connection refused'
      | token('\x06') -> 'TTL expired'
      | token('\x07') -> 'Command not supported'
      | token('\x08') -> 'Address type not supported'

serverReplyMessage =
    ver rep:reply rsv SOCKSAddress:address port:port
    -> (reply, address, port)
"""

SOCKSGrammar = parsley.makeGrammar(socks_grammar, {})

