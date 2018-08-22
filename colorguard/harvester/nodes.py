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
        return 4095 - idx // 8

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

    def _single_sided(self, op):
        """
        Check if a an AST contains the flag page on only one sided
        :param op: Node representing the operation to test
        :return: boolean whether symbolic data is only on a single side
        """


    def _concat_to_c(self):

        statements = [ ]

        max_op_size = 0

        for size, op in self.root.operands:

            statement = None
            # we can get operations where flag data is on both sides of arithmetic operation
            # these are not always impossible to reverse (for example flag_data + flag_data)
            # TODO: but im too lazy to special case these at the moment
            if isinstance(op, BVVNode) or op._symbolic_sides() > 1:
                # read and throw away
                statements.append("blank_receive(0, {});".format(size // 8))
            else:
                max_op_size = max(max_op_size, size // 8)
                # find extract to determine which flag byte
                statements.append("receive(0, {}, {}, NULL);\n".format('root', size // 8))

                enode = self._find_node(op, ExtractNode)
                start_byte = NodeTree._to_byte_idx(enode.end_index)
                end_byte = NodeTree._to_byte_idx(enode.start_index) + 1

                statement = op.to_statement()
                if statement != "":
                    statements.append(statement + ";")

                for r_i, i in enumerate(range(start_byte, end_byte)):
                    statement = ""
                    if not i in self.created_vars:
                        statement += "uint8_t "
                        self.created_vars.add(i)
                    # hack! this will assume that if the operation size is larger than leaked bytes
                    # the leaked bytes will be on the `right` of the leaked int
                    statement += "flag_byte_%d = root[%d] & 0xff;" % (i, r_i + (size // 8) - (end_byte - start_byte))
                    statements.append(statement)

        statements = ["\nchar root[%d];" % max_op_size, "int flag = 0;"] + statements
        return '\n'.join(statements) + "\n" + self._concat_combine_bytes()

    def _extract_to_c(self):

        # if it's an extract statement we already know it needs to have all the bytes

        statements = ["\nchar root[%d];" % (self.root.size // 8), "int flag = 0;"]
        statements.append("receive(0, {}, {}, NULL);".format('root', self.root.size // 8))

        statements.append(self.root.to_statement() + ";")
        for i in range(self.root.size // 8):
            statements.append("uint8_t flag_byte_%d = root[%d] & 0xff;" % (i, i))

        for i in range(min(self.root.size // 8, 4)):
            statements.append("flag |= flag_byte_%d << %d;" % (i, 24 - (i * 8)))
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

                bs = list(range(start_byte, end_byte+1))

                lbytes  += list(map(lambda y: (y, op), bs))

        return lbytes

    def _extract_leaked_bytes(self):
        """
        Simple for extract, just do operations based off the indices
        """

        start_byte = NodeTree._to_byte_idx(self.root.end_index)
        end_byte = NodeTree._to_byte_idx(self.root.start_index)

        return list(map(lambda y: (y, self.root), [start_byte] + list(range(start_byte + 1, end_byte + 1))))

    def _concat_combine_bytes(self):

        statements = [ ]
        ordered_bytes = dict(self.leaked_bytes())
        for current_byte in ordered_bytes:
            # check if the next four bytes leak the subsequent bytes
            current_byte_idx = current_byte

            next_consec = True

            for j in range(1,4):
                if not current_byte+j in ordered_bytes:
                    next_consec = False
                    break

            # try again
            if not next_consec:
                continue

            # found four consecutive bytes
            for j in range(0, 4):
                statements.append("flag |= " + "flag_byte_{} << {};".format(current_byte_idx + j, 24 - 8 * j))

            break

        if len(statements) == 0:
            raise ValueError("no consecutive four bytes")

        return '\n'.join(statements)

class Node(object):

    def __init__(self, size):
        self.size = size

    def _symbolic_sides(self):
        raise NotImplementedError("It is the responsibilty of subclasses to implement this method")

class UnOp(Node):

    def __init__(self, arg, size):
        super(UnOp, self).__init__(size)
        self.arg = arg

    def _symbolic_sides(self):
        return self.arg._symbolic_sides()

class BVVNode(UnOp):
    def __init__(self, arg, size):
        super(BVVNode, self).__init__(arg, size)

    def to_statement(self):
        return "{0:#x}".format(self.arg)

    def _symbolic_sides(self):
        return 0

class BVSNode(UnOp):
    def __init__(self, arg, size):
        super(BVSNode, self).__init__(arg, size)

    def to_statement(self):
        return self.arg

    def _symbolic_sides(self):
        return 1

class BinOpNode(Node):

    def __init__(self, op_str, arg1, arg2, size):
        super(BinOpNode, self).__init__(size)
        self.arg1 = arg1
        self.arg2 = arg2
        self.op_str = op_str

    def to_statement(self):
        a1_t = self.arg1.to_statement()
        a2_t = self.arg2.to_statement()
        return "{1}({0}, {2}, {3})".format(a1_t, self.op_str, a2_t, self.size // 8)

    def _symbolic_sides(self):
        return self.arg1._symbolic_sides() + self.arg2._symbolic_sides()

class AddNode(BinOpNode):

    def __init__(self, arg1, arg2, size):
        super(AddNode, self).__init__('add', arg1, arg2, size)

class SubNode(BinOpNode):

    def __init__(self, arg1, arg2, size):
        super(SubNode, self).__init__('sub', arg1, arg2, size)

class XorNode(BinOpNode):

    def __init__(self, arg1, arg2, size):
        super(XorNode, self).__init__('xor', arg1, arg2, size)

class AndNode(BinOpNode):
    def __init__(self, arg1, arg2, size):
        super(AndNode, self).__init__('and', arg1, arg2, size)

class ExtractNode(UnOp):

    def __init__(self, arg, start_index, end_index, size):
        super(ExtractNode, self).__init__(arg, size)
        self.start_index = start_index
        self.end_index = end_index

    def to_statement(self):
        """
        ExtractNodes are assumed to be top-level
        """

        a_t = self.arg.to_statement()

        if isinstance(self.arg, BVSNode):
            return ""

        return "{0}".format(a_t)

class ReverseNode(UnOp):

    def __init__(self, arg, size):
        super(ReverseNode, self).__init__(arg, size)

    def to_statement(self):
        a_t = self.arg.to_statement()
        return "reverse({0}, {1})".format(a_t, self.size // 8)

class ConcatNode(Node):

    def __init__(self, operands, size):
        super(ConcatNode, self).__init__(size)
        self.operands = operands

    def to_statement(self):
        raise NotImplementedError("this should not be called")

    def _symbolic_sides(self):
        """symbolicness does not matter in this case"""
        return 0
