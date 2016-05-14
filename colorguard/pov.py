from .harvester import Harvester
from .c_templates import c_template

class ColorguardType2Exploit(object):
    """
    A Type2 exploit created using the Colorgaurd approach.
    """

    def __init__(self, input_string, leaked_ast):
        self.input_string = input_string
        self.leaked_ast = leaked_ast

        node_tree = Harvester(leaked_ast).reverse()
        assert len(node_tree.leaked_bytes()) >= 4, "input does not leak enough bytes, 4 bytes required"

        self.transformation_code = node_tree.to_c()

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
        fmt_args["transformation_code"] = self.transformation_code

        c_code = c_template
        for k, v in fmt_args.items():
            c_code = c_code.replace("{%s}" % k, v)

        if filename is not None:
            with open(filename, 'w') as f:
                f.write(c_code)
        else:
            return c_code
