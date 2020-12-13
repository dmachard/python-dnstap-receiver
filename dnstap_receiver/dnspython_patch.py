
import dns.exception
import dns.opcode
import dns.flags

# waiting fix with dnspython 2.1
# will be removed in the future
class _WireReader(dns.message._WireReader):
    def read(self):
        """issue fixed - waiting fix with dnspython 2.1"""
        if self.parser.remaining() < 12:
            raise dns.message.ShortHeader
        (id, flags, qcount, ancount, aucount, adcount) = \
            self.parser.get_struct('!HHHHHH')
        factory = dns.message._message_factory_from_opcode(dns.opcode.from_flags(flags))
        self.message = factory(id=id)
        self.message.flags = flags
        self.initialize_message(self.message)
        self.one_rr_per_rrset = \
            self.message._get_one_rr_per_rrset(self.one_rr_per_rrset)
        self._get_question(dns.message.MessageSection.QUESTION, qcount)
        
        return self.message

# waiting fix with dnspython 2.1
# will be removed in the future
def from_wire(wire, question_only=True):
    """decode wire message - waiting fix with dnspython 2.1"""
    raise_on_truncation=False
    def initialize_message(message):
        message.request_mac = b''
        message.xfr = False
        message.origin = None
        message.tsig_ctx = None

    reader = _WireReader(wire, initialize_message, question_only=question_only,
                 one_rr_per_rrset=False, ignore_trailing=False,
                 keyring=None, multi=False)
    try:
        m = reader.read()
    except dns.exception.FormError:
        if reader.message and (reader.message.flags & dns.flags.TC) and \
           raise_on_truncation:
            raise dns.message.Truncated(message=reader.message)
        else:
            raise
    # Reading a truncated message might not have any errors, so we
    # have to do this check here too.
    if m.flags & dns.flags.TC and raise_on_truncation:
        raise dns.message.Truncated(message=m)

    return m
    