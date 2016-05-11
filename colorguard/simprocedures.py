import simuvex

class FlagLeakDetected(Exception):
    pass

class ColorGuardTransmitHook(simuvex.procedures.cgc.transmit.transmit):
    # pylint:disable=arguments-differ
    """
    Transmit simprocedure which detects leak of the flag page data
    """

    def run(self, fd, buf, count, tx_bytes):

        data = self.state.memory.load(buf, count)

        # check to see if any variable contain the flag page
        for var in list(data.variables):
            # did we find a leak?
            if var.split("_")[0] == 'cgc-flag-data':
                raise FlagLeakDetected(data)

        # run the actual transmit simprocedure
        return super(ColorGuardTransmitHook, self).run(fd, buf, count, tx_bytes)
