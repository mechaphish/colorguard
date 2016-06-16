from tracer.simprocedures.receive import FixedInReceive

import logging
l = logging.getLogger("colorguard.simprocedures.CacheReceive")

def cache_pass(_):
    l.warning("cache_hook never explicitly set")

# called when caching the state
cache_hook = cache_pass

class CacheReceive(FixedInReceive):
    # pylint:disable=arguments-differ
    """
    Receive which caches the state on it's first call (aka when internal file position is 0.
    """

    def run(self, fd, buf, count, rx_bytes):

        if self.state.se.any_int(self.state.posix.files[0].pos) == 0:
            if cache_hook is not None:
                cache_hook(self.state)

        ret = super(CacheReceive, self).run(fd, buf, count, rx_bytes)

        return ret
