import zlib

class crc:
    """
    Wraps up zlib.crc32 to make it suitable for use as a faster but less
    accurate alternative to the hashlib.* classes.
    """
    block_size = 64

    def __init__(self, initial=None):
        self.crc = 0
        if initial is not None:
            self.update(initial)

    def update(self, block):
        self.crc = zlib.crc32(block, self.crc)

    def hexdigest(self):
        return "%s" % ("00000000%x" % (self.crc & 0xffffffff))[-8:]

    def digest(self):
        # Er...
        return self.crc
