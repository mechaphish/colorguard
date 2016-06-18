import tempfile
import compilerex
from .harvester import Harvester
from .c_templates import c_template
from rex.pov_testing import CGCPovTester

import logging

l = logging.getLogger("colorguard.pov")

class ColorguardType2Exploit(object):
    """
    A Type2 exploit created using the Colorgaurd approach.
    """

    def __init__(self, binary, input_string, leaked_ast):
        self.binary = binary
        self.input_string = input_string
        self.leaked_ast = leaked_ast
        self.method_name = 'circumstantial'

        node_tree = Harvester(leaked_ast).reverse()
        assert len(node_tree.leaked_bytes()) >= 4, "input does not leak enough bytes, 4 bytes required"

        self.transformation_code = node_tree.to_c()

        l.debug("C Code: %s", self.transformation_code)

    def dump_c(self, filename=None):
        """
        Creates a simple C file to do the Type 2 exploit
        :return: the C code
        """

        encoded_payload = ""
        for c in self.input_string:
            encoded_payload += "\\x%02x" % ord(c)

        fmt_args = dict()
        fmt_args["payload"] = encoded_payload
        fmt_args["payloadsize"] = str(len(self.input_string))
        fmt_args["transformation_code"] = self.transformation_code

        c_code = c_template
        for k, v in fmt_args.items():
            c_code = c_code.replace("{%s}" % k, v)

        if filename is not None:
            with open(filename, 'w') as f:
                f.write(c_code)
        else:
            return c_code

    def dump_binary(self, filename=None):
        c_code = self.dump_c()
        compiled_result = compilerex.compile_from_string(c_code,
                                                         filename=filename)
        return compiled_result

    def test_binary(self):
        '''
        Test the binary generated
        '''

        # dump the binary code
        pov_binary_filename = tempfile.mktemp(dir='/tmp', prefix='colorguard-pov-')
        self.dump_binary(filename=pov_binary_filename)

        pov_tester = CGCPovTester()
        return pov_tester.test_binary_pov(pov_binary_filename, self.binary)
