from protobuf3.message import Message
from protobuf3.fields import Fixed32Field, UInt32Field, UInt64Field, EnumField, MessageField, BytesField
from enum import Enum


class Dnstap(Message):

    class Type(Enum):
        MESSAGE = 1


class Message(Message):

    class Type(Enum):
        AUTH_QUERY = 1
        AUTH_RESPONSE = 2
        RESOLVER_QUERY = 3
        RESOLVER_RESPONSE = 4
        CLIENT_QUERY = 5
        CLIENT_RESPONSE = 6
        FORWARDER_QUERY = 7
        FORWARDER_RESPONSE = 8
        STUB_QUERY = 9
        STUB_RESPONSE = 10
        TOOL_QUERY = 11
        TOOL_RESPONSE = 12
        UPDATE_QUERY = 13
        UPDATE_RESPONSE = 14


class SocketFamily(Enum):
    INET = 1
    INET6 = 2


class SocketProtocol(Enum):
    UDP = 1
    TCP = 2

Dnstap.add_field('identity', BytesField(field_number=1, optional=True))
Dnstap.add_field('version', BytesField(field_number=2, optional=True))
Dnstap.add_field('extra', BytesField(field_number=3, optional=True))
Dnstap.add_field('type', EnumField(field_number=15, required=True, enum_cls=Dnstap.Type))
Dnstap.add_field('message', MessageField(field_number=14, optional=True, message_cls=Message))
Message.add_field('type', EnumField(field_number=1, required=True, enum_cls=Message.Type))
Message.add_field('socket_family', EnumField(field_number=2, optional=True, enum_cls=SocketFamily))
Message.add_field('socket_protocol', EnumField(field_number=3, optional=True, enum_cls=SocketProtocol))
Message.add_field('query_address', BytesField(field_number=4, optional=True))
Message.add_field('response_address', BytesField(field_number=5, optional=True))
Message.add_field('query_port', UInt32Field(field_number=6, optional=True))
Message.add_field('response_port', UInt32Field(field_number=7, optional=True))
Message.add_field('query_time_sec', UInt64Field(field_number=8, optional=True))
Message.add_field('query_time_nsec', Fixed32Field(field_number=9, optional=True))
Message.add_field('query_message', BytesField(field_number=10, optional=True))
Message.add_field('query_zone', BytesField(field_number=11, optional=True))
Message.add_field('response_time_sec', UInt64Field(field_number=12, optional=True))
Message.add_field('response_time_nsec', Fixed32Field(field_number=13, optional=True))
Message.add_field('response_message', BytesField(field_number=14, optional=True))
