import struct
import logging

# https://farsightsec.github.io/fstrm/

# Frame Streams Control Frame Format - Data frame length equals 00 00 00 00

# |------------------------------------|----------------------|
# | Data frame length                  | 4 bytes              |  
# |------------------------------------|----------------------|
# | Control frame length               | 4 bytes              |
# |------------------------------------|----------------------|
# | Control frame type                 | 4 bytes              |
# |------------------------------------|----------------------|
# | Control frame content type         | 4 bytes (optional)   |
# |------------------------------------|----------------------|
# | Control frame content type length  | 4 bytes (optional)   |
# |------------------------------------|----------------------|
# | Content type payload               | xx bytes             |     
# |------------------------------------|----------------------|

# Frame Streams Data Frame Format

# |------------------------------------|----------------------|
# | Data frame length                  | 4 bytes              |
# |------------------------------------|----------------------|
# | Payload - Protobuf                 | xx bytes             |
# |------------------------------------|----------------------|

FSTRM_DATA_FRAME = 0
FSTRM_CONTROL_ACCEPT = 1
FSTRM_CONTROL_START = 2
FSTRM_CONTROL_STOP = 3
FSTRM_CONTROL_READY = 4
FSTRM_CONTROL_FINISH = 5

FSTRM_FRAME_TYPES = {
    FSTRM_DATA_FRAME,
    FSTRM_CONTROL_ACCEPT,
    FSTRM_CONTROL_START, 
    FSTRM_CONTROL_STOP,
    FSTRM_CONTROL_READY,
    FSTRM_CONTROL_FINISH
}

FSTRM_CONTROL_FIELD_CONTENT_TYPE = 1
# CONTENT_TYPE_DNSTAP = "protobuf:dnstap.Dnstap"

class FstrmHandler(object):
    """frame stream decoder/encoder"""
    def __init__(self):
        """init class"""
        self.buf = b''
        
        self.df_length = None
        self.cf_length = None
        
    def reset(self):
        """reset"""
        self.df_length = None
        self.cf_length = None
        
    def pending_nb_bytes(self):
        """returns number of bytes remaining pending"""
        if self.df_length is not None:
            if self.df_length > 0:
                return self.df_length - len(self.buf)

        if self.cf_length is not None:
            if self.cf_length > 0:
                return self.cf_length - len(self.buf)
                
        return 4
        
    def append(self, data):
        """append data to the buffer"""
        self.buf = b''.join([self.buf, data])
        
    def process(self):
        """process the buffer"""
        if self.df_length is None:
            # need more data ?
            if len(self.buf) < 4:
                return False 
        
            # enough data, decode frame length
            (self.df_length,) = struct.unpack("!I", self.buf[:4])
            self.buf = self.buf[4:]
   
        # control frame ?
        if self.df_length == 0:
            # need more data ?
            if len(self.buf) < 4:
                return False
            
            if self.cf_length is None:
                (self.cf_length,) = struct.unpack("!I", self.buf[:4])
                self.buf = self.buf[4:]
            
            # need more data ?
            if len(self.buf) < self.cf_length:
                return False
            # we have received enough data, the frame is complete
            return True
            
        else:
            # need more data ?
            if len(self.buf) < self.df_length:
                return False
            else:
                return True
                
    def decode(self):
        """decode frame"""
        is_cf = False
        
        # read frame from buffer
        if self.df_length == 0:
            frame = self.buf[:self.cf_length]
            self.buf = self.buf[self.cf_length:]
            is_cf = True
        else:
            frame = self.buf[:self.df_length]
            self.buf = self.buf[self.df_length:]

        # reset to process next frame
        self.df_length = None
        self.cf_length = None
        
        # data frame ?
        if not is_cf: return (FSTRM_DATA_FRAME, [], frame)
            
        # decode control frame
        (ctrl,) = struct.unpack("!I", frame[:4])
        frame = frame[4:]
        
        ct = []
        while len(frame) > 8:
            (cf_ctype, cf_clength,) = struct.unpack("!II", frame[:8])
            frame = frame[8:]
            
            if cf_ctype != FSTRM_CONTROL_FIELD_CONTENT_TYPE:
                raise Exception("control ready - content type invalid")
            if cf_clength > len(frame):
                raise Exception("control ready - content length invalid")
                
            ct.append(frame[:cf_clength]) 
            frame = frame[cf_clength:]

        return (ctrl, ct, frame)

    def encode(self, ctrl, ct=[], payload=b""):
        """encode"""
            
        if ctrl not in FSTRM_FRAME_TYPES:
            raise Exception("frame not supported: %s" % ctrl)
           
        # data frame ?
        if ctrl == FSTRM_DATA_FRAME:
            frame = struct.pack('!I', len(payload))
            frame += payload
            return frame
 
        # control frame ?
        length = 4 + 8*len(ct) + len(b"".join(ct))
        frame = struct.pack('!III', 0, length, ctrl)
        for c in ct:
            frame += struct.pack('!II', FSTRM_CONTROL_FIELD_CONTENT_TYPE, len(c))
            frame += c   

        return frame
