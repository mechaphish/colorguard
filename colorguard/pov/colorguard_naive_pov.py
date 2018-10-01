import angr
import compilerex
from .fake_crash import FakeCrash
from rex.exploit.cgc import CGCExploit
from .c_templates import naive_c_template

import logging

l = logging.getLogger("colorguard.pov.ColorguardNaiveExploit")

class ColorguardNaiveExploit(CGCExploit):
    """
    A Type2 exploit created using the Naive approach.
    """

    def __init__(self, binary, payload, stdout_len, leaked_bytes):
        """
        :param binary: path to binary
        :param payload: string which causes the leak when used as input to the binary
        :param stdout_len: length of stdout
        :param leaked_bytes: list of indices of the stdout which leaked
        """
        # fake crash object
        crash = FakeCrash(binary, angr.Project(binary).factory.entry_state())
        super(ColorguardNaiveExploit, self).__init__(crash, cgc_type=2, bypasses_nx=True, bypasses_aslr=True)

        self.binary = binary
        self.payload = payload
        self._payload_len = len(payload)
        self.method_name = 'circumstantial'
        self._recv_buf_len = stdout_len

        self._flag_byte_1 = leaked_bytes[0]
        self._flag_byte_2 = leaked_bytes[1]
        self._flag_byte_3 = leaked_bytes[2]
        self._flag_byte_4 = leaked_bytes[3]

    def dump_c(self, filename=None):
        """
        Creates a simple C file to do the Type 2 exploit
        :return: the C code
        """

        encoded_payload = ""
        for c in self.payload:
            encoded_payload += "\\x%02x" % c

        fmt_args = dict()
        fmt_args["raw_payload"] = encoded_payload
        fmt_args["payload_len"] = hex(self._payload_len)
        fmt_args["recv_buf_len"] = hex(self._recv_buf_len)
        fmt_args["flag_byte_1"] = hex(self._flag_byte_1)
        fmt_args["flag_byte_2"] = hex(self._flag_byte_2)
        fmt_args["flag_byte_3"] = hex(self._flag_byte_3)
        fmt_args["flag_byte_4"] = hex(self._flag_byte_4)

        c_code = naive_c_template
        for k, v in fmt_args.items():
            c_code = c_code.replace("{%s}" % k, v)

        if filename is not None:
            with open(filename, 'w') as f:
                f.write(c_code)
        else:
            return c_code

    def dump_python(self, filename=None):
        raise NotImplementedError

    def dump_binary(self, filename=None):
        c_code = self.dump_c()
        compiled_result = compilerex.compile_from_string(c_code,
                                                         filename=filename)

        if filename:
            return None

        return compiled_result
