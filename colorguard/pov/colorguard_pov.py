import compilerex
from .fake_crash import FakeCrash
from rex.exploit.cgc import CGCExploit
from .c_templates import colorguard_c_template

import logging

l = logging.getLogger("colorguard.pov.ColorguardExploit")

class ColorguardExploit(CGCExploit):
    """
    A Type2 exploit created using the Colorgaurd approach.
    """

    def __init__(self, binary, state, input_string, harvester, leak_ast, output_var):
        """
        :param binary: path to binary
        :param state: a state after the trace
        :param input_string: string which causes the leak when used as input to the binary
        :param harvester: AST harvester object
        :param leak_ast: the ast that is leaked
        :param output_var: clarpiy output variable
        """
        # fake crash object
        crash = FakeCrash(binary, state)
        super(ColorguardExploit, self).__init__(crash, cgc_type=2, bypasses_nx=True, bypasses_aslr=True)

        self.binary = binary
        self.input_string = input_string
        self.harvester = harvester
        self.output_var = output_var
        self.method_name = 'circumstantial'

        leaked_bytes = harvester.get_largest_consecutive()
        assert len(leaked_bytes) >= 4, "input does not leak enough bytes, 4 bytes required"

        self._arg_vars = [output_var]
        self._mem = leak_ast
        self._flag_var_name = filter(lambda x: x.startswith("cgc-flag"), leak_ast.variables)[0]

        self._generate_formula(extra_flag_solve=True)

        self._byte_getting_code = self._generate_byte_getting_code()

        self._flag_byte_1 = leaked_bytes[0]
        self._flag_byte_2 = leaked_bytes[1]
        self._flag_byte_3 = leaked_bytes[2]
        self._flag_byte_4 = leaked_bytes[3]

    def _generate_byte_getting_code(self):

        byte_getters = [ ]
        for b in sorted(self.harvester.output_bytes):
            byte_getters.append("append_byte_to_output(btor, %d);" % b)

        return "\n".join(byte_getters)

    def dump_c(self, filename=None):
        """
        Creates a simple C file to do the Type 2 exploit
        :return: the C code
        """

        encoded_payload = ""
        for c in self.input_string:
            encoded_payload += "\\x%02x" % ord(c)

        fmt_args = dict()
        fmt_args["raw_payload"] = encoded_payload
        fmt_args["payload_len"] = hex(self._payload_len)
        fmt_args["payloadsize"] = hex(len(self.input_string))
        fmt_args["output_size"] = hex(len(self.harvester.output_bytes)*8)
        fmt_args["solver_code"] = self._solver_code
        fmt_args["recv_buf_len"] = hex(self._recv_buf_len)
        fmt_args["byte_getting_code"] = self._byte_getting_code
        fmt_args["flag_byte_1"] = hex(self._flag_byte_1)
        fmt_args["flag_byte_2"] = hex(self._flag_byte_2)
        fmt_args["flag_byte_3"] = hex(self._flag_byte_3)
        fmt_args["flag_byte_4"] = hex(self._flag_byte_4)
        fmt_args["btor_name"] = self._formulas[-1].name
        fmt_args["cgc_flag_data_idx"] = str(self._formulas[-1].name_to_id[self._flag_var_name])

        # int stuff
        fmt_args["payload_int_start_locations"] = self._make_c_int_arr([x.start for x in self._sorted_stdin_int_infos])
        fmt_args["payload_int_bases"] = self._make_c_int_arr([x.base for x in self._sorted_stdin_int_infos])
        fmt_args["payload_int_expected_lens"] = self._make_c_int_arr([x.size for x in self._sorted_stdin_int_infos])
        fmt_args["recv_int_start_locations"] = self._make_c_int_arr([x.start for x in self._sorted_stdout_int_infos])
        fmt_args["recv_int_bases"] = self._make_c_int_arr([x.base for x in self._sorted_stdout_int_infos])
        fmt_args["recv_int_expected_lens"] = self._make_c_int_arr([x.size for x in self._sorted_stdout_int_infos])
        fmt_args["num_payload_ints"] = str(len(self._sorted_stdin_int_infos))
        fmt_args["num_recv_ints"] = str(len(self._sorted_stdout_int_infos))


        c_code = colorguard_c_template
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
