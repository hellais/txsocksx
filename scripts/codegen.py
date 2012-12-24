

def makeTestFailure():
    l = ['ServerFailure',
         'ConnectionNotAllowed',
         'NetworkUnreachable',
         'HostUnreachable',
         'ConnectionRefused',
         'TTLExpired',
         'CommandNotSupported',
         'AddressNotSupported']

    base = """
        def test_ServerReply%(error_name)s(self):
            p = SOCKSGrammar(dummyServerReplyFail%(idx)sIPV4)
            failure, addr, port  = p.serverReply()
            self.assertIs(failure, e.%(error_name)s)
    """
    for i, v in enumerate(l):
        print base % {'idx': i+1, 'error_name': v}

def errorTrappingFunctions():
    import re
    def convert(name):
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

    l = ['ServerFailure',
         'ConnectionNotAllowed',
         'NetworkUnreachable',
         'HostUnreachable',
         'ConnectionRefused',
         'TTLExpired',
         'CommandNotSupported',
         'AddressNotSupported']

    base = """
    elif isinstance(failure.value, %(error_name)s):
        log.err("SOCKS error: %(error_name)s")
        string = 'socks_%(error_string)s'
    """
    for i, v in enumerate(l):
        error_string = convert(v)
        print base % {'error_name': v, 'error_string': error_string}

errorTrappingFunctions()
