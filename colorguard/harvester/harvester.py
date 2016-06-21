import claripy
from .nodes import NodeTree
from .nodes import BVVNode, BVSNode
from .nodes import ReverseNode, AddNode, AndNode, SubNode, XorNode, ExtractNode, ConcatNode

class Harvester(object):
    """
    angr AST to a forward operation
    """

    def __init__(self, ast):
        self.ast = ast

        self.ast_var = claripy.BVS('reverse_root', 32)
        self.root = BVSNode('root', ast.size() / 8)
        self.tree = [ ]

    @staticmethod
    def determine_args(args):

        a1 = args[0]
        a2 = args[1]

        if a1.op == 'BVV':
            argument = a1
            data = a2
        else:
            argument = a2
            data = a1

        return argument, data

    def _reverse_inner(self, root=None, ast=None):
        """
        Recursive descent.

        push inverse operation and arguments for each op in original tree
        """

        if root is None:
            root = self.root

        if ast is None:
            ast = self.ast

        op = ast.op

        data = None
        if op == 'BVV':
            data = BVVNode(ast.args[0], ast.size())

        if op == 'BVS':
            data = BVSNode(ast.args[0], ast.size())

        ### OPERATIONS

        # two args, one is a constant
        if op == '__add__':

            new_root = root
            args = ast.args[1:]
            for arg in args:
                new_root = SubNode(new_root, self._reverse_inner(root, arg), ast.size())

            data = self._reverse_inner(new_root, ast.args[0])

        if op == '__sub__':

            new_root = root
            args = ast.args[1:]
            for arg in args:
                new_root = AddNode(new_root, self._reverse_inner(root, arg), ast.size())

            data = self._reverse_inner(new_root, ast.args[0])

        if op == '__xor__':

            new_root = root
            args = ast.args[1:]
            for arg in args:
                new_root = XorNode(new_root, self._reverse_inner(root, arg), ast.size())

            data = self._reverse_inner(new_root, ast.args[0])

        ### FUNCTIONS

        # three args, end index, start index, data
        if op == 'Extract':
            end_index = ast.args[0]
            start_index = ast.args[1]
            new_root = ExtractNode(root, start_index, end_index, ast.size())

            data = self._reverse_inner(new_root, ast.args[2])

            # special case if the extract is on the flag page
            if isinstance(data, BVSNode):
                data = new_root

        # only one arg
        if op == 'Reverse':
            # reverse takes a size as an argument
            new_root = ReverseNode(root, ast.args[0].size())

            data = self._reverse_inner(new_root, ast.args[0])

        ### SPECIAL

        if op == 'SignExt' or op == 'ZeroExt':
            # this consists of just removing the sign extension by anding with the
            # none extended bits

            size = ast.args[0]
            data = ast.args[1]

            new_root = AndNode(root, BVVNode((1 << (ast.size() - size)) - 1, ast.size()), ast.size())

            data = self._reverse_inner(new_root, data)

        if op == 'Concat':

            operands = [ ]
            for arg in ast.args:
                operands.append((arg.size(), self._reverse_inner(root, arg)))

            data = ConcatNode(operands, ast.size())
            # no more processing

        assert data is not None, "unsupported op type '%s' encountered" % op

        return data

    def reverse(self):

        # assume transformed flag data is in `flag_data`
        return NodeTree(self._reverse_inner())
