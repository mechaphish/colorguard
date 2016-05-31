class NodeTree(object):
    """
    Tree of node objects, responsible for turning operation nodes into C code.
    """

    def __init__(self, node_root):

        if not isinstance(node_root, (ConcatNode, ExtractNode)):
            raise ValueError("only ConcatNodes or ExtractNodes can be tree roots")

        self.root = node_root
        self.created_vars = set()

    @staticmethod
    def _to_byte_idx(idx):
        return 4095 - idx / 8

    def _find_node(self, tree, node_cls):

        if isinstance(tree, node_cls):
            return tree

        if isinstance(tree, BinOpNode):
            res = self._find_node(tree.arg1, node_cls)
            if res is not None:
                return res
            res = self._find_node(tree.arg2, node_cls)

        if isinstance(tree, ReverseNode):
            return self._find_node(tree.arg, node_cls)

        if isinstance(tree, ExtractNode):
            return self._find_node(tree.arg, node_cls)

        if isinstance(tree, (BVSNode, BVVNode)):
            return None

    def to_c(self):
        """
        Convert a C expression.
        """

        c_code = None
        if isinstance(self.root, ConcatNode):
            c_code = self._concat_to_c()
        elif isinstance(self.root, ExtractNode):
            c_code = self._extract_to_c()
        else:
            assert False, "unrecognized node type %s as op" % self.root.__class__

        return c_code

    def _concat_to_c(self):

        statements = ["int root, flag;", "root = flag = 0;"]
        need_vars = [ ]
        for size, op in self.root.operands:

            statement = None
            if isinstance(op, BVVNode):
                # read and throw away
                statement = "blank_receive(0, {});".format(size / 8)
            else:
                # find extract to determine which flag byte
                statement  = "receive(0, &{}, {}, NULL);\n".format('root', size / 8)

                enode = self._find_node(op, ExtractNode)
                start_byte = NodeTree._to_byte_idx(enode.end_index)
                end_byte = NodeTree._to_byte_idx(enode.start_index) + 1

                b_str = str(start_byte)
                if start_byte != end_byte - 1:
                    b_str = '_'.join(map(str, range(start_byte, end_byte)))

                need_vars.append(("flag_byte_%s" % b_str, range(start_byte, end_byte)))
                self.created_vars.add(tuple(range(start_byte, end_byte)))

                statement += "int flag_byte_" + b_str + " = "
                statement += op.to_statement() + ";"

            statements.append(statement)

        return '\n'.join(statements) + "\n" + self._concat_combine_bytes(need_vars)

    def _extract_to_c(self):

        # if it's an extract statement we already know it needs to have all the bytes

        statements = ["int root, flag;", "root = flag = 0;"]
        statements.append("receive(0, &{}, 4, NULL);".format('root'))
        statements.append("flag = " + self.root.to_statement() + ";")
        return "\n".join(statements)

    def leaked_bytes(self):
        """
        Determine which bytes were leaked
        :returns: list of tuples of (byte_index, operation)
        """

        byte_list = [ ]
        if isinstance(self.root, ConcatNode):
            byte_list = self._concat_leaked_bytes()
        elif isinstance(self.root, ExtractNode):
            byte_list = self._extract_leaked_bytes()

        return byte_list

    def _concat_leaked_bytes(self):
        """
        Traverse tree and determine which byte indices of the flag page were leaked.
        :returns: list of tuples of (byte_index, operation)
        """

        lbytes = [ ]
        op = None # silence pylint
        for _, op in self.root.operands:

            node = self._find_node(op, ExtractNode)
            if node is not None:
                start_byte = NodeTree._to_byte_idx(node.end_index)
                end_byte = NodeTree._to_byte_idx(node.start_index)

                bs = range(start_byte, end_byte+1)

                lbytes  += map(lambda y: (y, op), bs)

        return lbytes

    def _extract_leaked_bytes(self):
        """
        Simple for extract, just do operations based off the indices
        """

        start_byte = NodeTree._to_byte_idx(self.root.end_index)
        end_byte = NodeTree._to_byte_idx(self.root.start_index)

        return map(lambda y: (y, self.root), [start_byte] + range(start_byte + 1, end_byte + 1))

    def _to_single_byte_vars(self, need_vars):

        created_singletons = set()
        for varset in self.created_vars:
            if len(varset) == 1:
                created_singletons.add(varset[0])

        statements = [ ]

        for varname, varset in need_vars:
            for i, var in enumerate(varset):

                if not var in created_singletons:
                    statement  = "int flag_byte_%d = " % var
                    statement += "(%s & (0xff << %d)) >> %d;" % (varname, i * 8, i * 8)
                    statements.append(statement)
                    created_singletons.add(var)

        return statements

    def _concat_combine_bytes(self, need_vars):

        statements = self._to_single_byte_vars(need_vars)

        ordered_bytes = sorted(self.leaked_bytes())
        for i, current_byte in enumerate(ordered_bytes):
            # check if the next four bytes leak the subsequent bytes
            current_byte_idx = current_byte[0]

            try:
                next_consec = True
                for j in range(1,4):
                    if current_byte_idx + j != ordered_bytes[i+j][0]:
                        next_consec = False
                        break
            except IndexError:
                raise ValueError("no consecutive four bytes")

            # try again
            if not next_consec:
                continue

            # found four consecutive bytes
            for j in range(0, 4):
                statements.append("flag |= " + "flag_byte_{} << {};".format(current_byte_idx + j, 8 * j))

            break

        if len(statements) == 0:
            raise ValueError("no consecutive four bytes")

        return '\n'.join(statements)

class Node(object):
    pass

class BinOpNode(Node):

    def __init__(self, op_str, arg1, arg2):
        self.arg1 = arg1
        self.arg2 = arg2
        self.op_str = op_str

    def to_statement(self):
        a1_t = self.arg1.to_statement()
        a2_t = self.arg2.to_statement()
        return "({0} {1} {2})".format(a1_t, self.op_str, a2_t)

class ReverseNode(Node):

    def __init__(self, arg, size):
        self.size = size
        self.arg = arg

    def to_statement(self):
        a_t = self.arg.to_statement()
        #return "reverse({0}, {1})".format(a_t, self.size / 8)
        return "{0}".format(a_t)

class BVVNode(Node):
    def __init__(self, arg):
        self.arg = arg

    def to_statement(self):
        return "{0:#x}".format(self.arg)

class BVSNode(Node):
    def __init__(self, arg):
        self.arg = arg

    def to_statement(self):
        return self.arg

class AddNode(BinOpNode):

    def __init__(self, arg1, arg2):
        super(AddNode, self).__init__('+', arg1, arg2)

class SubNode(BinOpNode):

    def __init__(self, arg1, arg2):
        super(SubNode, self).__init__('-', arg1, arg2)

class XorNode(BinOpNode):

    def __init__(self, arg1, arg2):
        super(XorNode, self).__init__('^', arg1, arg2)

class AndNode(BinOpNode):
    def __init__(self, arg1, arg2):
        super(AndNode, self).__init__('&', arg1, arg2)

class ExtractNode(Node):

    def __init__(self, arg, start_index, end_index):
        self.arg = arg
        self.start_index = start_index
        self.end_index = end_index

    def to_statement(self):
        """
        ExtractNodes are assumed to be top-level
        """

        a_t = self.arg.to_statement()
        return "{0}".format(a_t)

class ConcatNode(Node):

    def __init__(self, operands):
        self.operands = operands

    def to_statement(self):
        raise NotImplementedError, "this should not be called"
