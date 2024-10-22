import sys
from typing import Optional


class Node:

    def __init__(self, mem_addr: int, mem_size: int, parent):
        self._mem_addr = mem_addr
        self._mem_size = mem_size
        self._left = None
        self._right = None
        #Added in order to delete a node easier
        self._parent = parent
        self._line = 1
        self._column = 1

    @property
    def address(self):
        return self._mem_addr

    @property
    def size(self):
        return self._mem_size

    @property
    def left(self):
        return self._left

    @property
    def right(self):
        return self._right

    @property
    def parent(self):
        return self._parent

    @property
    def line(self):
        return self._line

    @property
    def column(self):
        return self._column

    @property
    def key(self):
        return f'c_{self._line}_{self._column}'

    def __str__(self):
        p = self._parent.address if self._parent is not None else "N/A"
        l = self._left.address if self._left is not None else "N/A"
        r = self._right.address if self._right is not None else "N/A"
        return f"Node <{self._mem_addr}, P:{p}, L:{l}, R:{r}, S:{self.size} Key:{self.key}>"

    def set_left(self, left):
        self._left = left
        if left is not None:
            left.set_parent(self)

    def set_right(self, right):
        self._right = right
        if right is not None:
            right.set_parent(self)

    def set_parent(self, parent):
        self._parent = parent
        #print("set_parent", self, self._parent, self._line, self._column)
        self._line = self._parent.line + 1 if self._parent is not None else 1

    def set_column(self, column):
        self._column = column

    def get_min(self):
        mi = self
        n = self
        while n is not None:
            if n.address < mi.address:
                mi = n
            n = n.left

        n = self
        while n is not None:
            if n.address < mi.address:
                mi = n
            n = n.right

        return mi

    def get_max(self):
        mx = self
        n = self
        while n is not None:
            if n.address > mx.address:
                mx = n
            n = n.right

        n = self
        while n is not None:
            if n.address > mx.address:
                mx = n
            n = n.left

        return mx

    def clean(self):
        self._left = None
        self._right = None
        self._parent = None
        self._line = 1
        self._column = 1


class BinarySearchTree:

    def __init__(self):
        self.root = None
        self.nodes = []
        self.last = 0

    def build(self) -> bool:
        for n in self.nodes:
            n.clean()

        self.root = self._calc_left()

        if self.root is None:
            return False

        self._calc_left(self.root)
        self._calc_right(self.root)

        if self.root.left is not None:
            self.root.left.set_column(1)

        if self.root.right is not None:
            self.root.right.set_column(2)

        return self._build()

    def get_next(self):
        if self.last >= len(self.nodes):
            return None
        node = self.nodes[self.last]
        self.last += 1
        return node

    def _build(self) -> bool:
        while (node := next(iter([
            n
            for n in self.nodes
            if n.address != self.root.address
            and n.parent is not None
            and (
                    (n.left is None and any(iter(
                        True
                        for n1 in self.nodes
                        if n1.address != self.root.address
                        and n1.parent is None
                        and n1.address < n.address
                        and (n.parent.address > n.address or n1.address > n.parent.address)
                        and (self.root.address > n.address or n1.address > self.root.address)
                    )))
                    or (n.right is None and any(iter(
                        True
                        for n1 in self.nodes
                        if n1.address != self.root.address
                        and n1.parent is None
                        and n1.address > n.address
                        and (n.parent.address < n.address or n1.address < n.parent.address)
                        and (self.root.address < n.address or n1.address < self.root.address)
                    )))
               )
        ]), None)) is not None:
            self._calc_left(node)
            self._calc_right(node)
            if node.left is not None:
                node.left.set_column(1 if node.column == 1 else node.column + 1)

            if node.right is not None:
                node.right.set_column(node.column * 2)

        self.nodes = sorted(self.nodes, key=lambda x: f"{x.line:05d}_{x.address:010d}", reverse=False)

        return True

    def _calc_left(self, node: Node = None) -> Optional[Node]:
        if len(self.nodes) == 0:
            return None

        ri = [
            n for n in self.nodes
            if (self.root is None or n.address != self.root.address)
            and (node is None or n.address < node.address)
            and (
                       node is None or node.parent is None
                       or node.parent.address > node.address or n.address > node.parent.address
               )
            and (
                       node is None or self.root is None
                       or self.root.address < node.address or n.address < self.root.address
               )
            and n.parent is None
        ]

        m1 = next(iter(sorted(ri, key=lambda x: x.address, reverse=False)), None)
        m2 = next(iter(sorted(ri, key=lambda x: x.address, reverse=True)), None)
        if m1 is None or m2 is None:
            return None
        if m1 == m2:
            if node is not None:
                node.set_left(m1)
                #self._calc_left(m1)
                #self._calc_right(m1)
            return m1
        m3 = int(m1.address + ((m2.address - m1.address)/2))
        left = next(iter(sorted([
            n
            for n in ri
            if m1.address <= n.address <= m3
        ], key=lambda x: x.address, reverse=True)), None)
        if node is not None:
            node.set_left(left)
            #self._calc_left(left)
            #self._calc_right(left)
        return left

    def _calc_right(self, node: Node = None) -> Optional[Node]:
        if len(self.nodes) == 0:
            return None

        ri = [
            n for n in self.nodes
            if (self.root is None or n.address != self.root.address)
               and (node is None or n.address > node.address)
               and (
                       node is None or node.parent is None
                       or node.parent.address < node.address or n.address < node.parent.address
               )
               and (
                       node is None or self.root is None
                       or self.root.address > node.address or n.address > self.root.address
               )
               and n.parent is None
        ]

        m1 = next(iter(sorted(ri, key=lambda x: x.address, reverse=False)), None)
        m2 = next(iter(sorted(ri, key=lambda x: x.address, reverse=True)), None)
        if m1 is None or m2 is None:
            return None
        if m1 == m2:
            if node is not None:
                node.set_right(m1)
                #self._calc_left(m1)
                #self._calc_right(m1)
            return m1
        m3 = int(m1.address + ((m2.address - m1.address)/2))
        right = next(iter(sorted([
            n
            for n in ri
            if m1.address <= n.address <= m3
        ], key=lambda x: x.address, reverse=False)), None)
        if node is not None:
            node.set_right(right)
            #self._calc_left(right)
            #self._calc_right(right)
        return right

    def insert(self, mem_addr: int, mem_size: int):
        if self.get_node(mem_addr) is None:
            self.nodes.append(Node(mem_addr, mem_size, None))

    def delete(self, mem_addr: int, delete_children: bool = False):
        if not self.empty():
            #Look for the node with that label
            node = self._pop(mem_addr)
            #If the node exists
            if node is not None:
                if delete_children:
                    del_list = [node]
                    while len(ic := [
                        n
                        for n in self.nodes
                        if any(iter([
                            True for n1 in del_list if n.parent is not None and n.parent.address == n1.address]))
                        and next(iter([False for n1 in del_list if n.address == n1.address]), True)
                    ]) > 0:
                        del_list += ic

                    self.__reassign_nodes(node, None)
                    for n in del_list:
                        try:
                            self.nodes.pop(self.nodes.index(n))
                        except ValueError:
                            pass

                    self.build()


                else:
                    #If it has no children
                    if node.left is None and node.right is None:
                        self.__reassign_nodes(node, None)
                        node = None
                    #Has only right children
                    elif node.left is None and node.right is not None:
                        self.__reassign_nodes(node, node.right)
                    #Has only left children
                    elif node.left is not None and node.right is None:
                        self.__reassign_nodes(node, node.left)
                    #Has two children
                    else:
                        if node.line <= 2:
                            self.build()
                        else:
                            for n in self.nodes:
                                if n.line >= node.line:
                                    n.clean()
                            self._build()

    def get_node(self, mem_addr: int):
        return next(iter([n for n in self.nodes if n.address == mem_addr]), None)

    def _pop(self, mem_addr: int):
        node = self.get_node(mem_addr)
        if node is not None:
            self.nodes.pop(self.nodes.index(node))
        return node

    def _calc_depth(self, node):
        if node is None:
            return 0

        llv = 0
        rlv = 0

        if (l1 := node.left) is not None:
            llv += 1
            llv += self._calc_depth(l1)

        if (r1 := node.right) is not None:
            rlv += 1
            llv += self._calc_depth(r1)

        return llv if llv > rlv else rlv

    def draw_tree(self) -> str:
        if self.empty():
            return "Empty"

        mx = str(self.getMax().address)
        m1 = len(mx) + 6
        m1 += (2 - (m1 % 2)) #Keep symetry
        m2 = m1 - 6

        depth = max([1] + [n.line for n in self.nodes])
        max_col = max([1 << i for i in range(0, depth)])

        line_size = max_col * m1
        lines = [
            (" " * int((line_size-m1)/2)) + f"c_1_1"
            ]

        txt_tree = " " * (int(max_col/2) * m1)
        txt_tree += f"| {self.root.address} |\n"
        for i in range(1, depth):
            txt_tree += " " * (int(depth/(i*2)) * m1)
            txt_tree += f" " * (m1 - 1)
            txt_tree += "_" * (int((depth-1) / (i*2)) * m1)
            txt_tree += f"/\n"

            txt_tree += " " * (int(depth / (i*2)) * m1)
            txt_tree += f"| {i} |\n"

        #txt_tree = ""

        for i in range(1, depth):
            c = 1 << i
            lt = ("".join([
                "___",
                f"=".center(m2, '_'),
                "___"
            ])).center(int(line_size/c), ' ').replace('_', '')
            lines += [
                ''.join(
                    [
                        lt.replace('=', f'c_{i+1}_{ci}')
                        for ci in range(1, c+1)
                    ]
                )
            ]

        txt_tree = '\n'.join(lines) + '\n'

        values = {
            n.key: n.address
            for n in self.nodes
        }

        for i in range(1, depth + 1):
            c = 1 << i
            for ci in range(1, c + 1):
                k = f'c_{i}_{ci}'
                v = values.get(k, None)
                txt_tree = txt_tree.replace(
                    k,
                    f" | {str(v).rjust(m2, '0')} | " if v is not None
                    else f"   {str('').rjust(m2, ' ')}   "
                )

        for i in range(0, depth):
            f = 1 << i
            #txt_tree += f"D {i} {f}\n"
            
        return txt_tree

    def getMax(self, root: Node = None):
        if root is not None:
            curr_node = root
        else:
            #We go deep on the right branch
            curr_node = self.getRoot()
        return next(iter(sorted([
            n for n in self.nodes
            if (root is None or n.address > root.address)
        ], key=lambda x: x.address, reverse=True)), curr_node)

    def getMin(self, root: Node = None):
        if root is not None:
            curr_node = root
        else:
            #We go deep on the left branch
            curr_node = self.getRoot()
        return next(iter(sorted([
            n for n in self.nodes
            if (root is None or n.address < root.address)
        ], key=lambda x: x.address, reverse=False)), curr_node)

    def empty(self):
        if self.root is None:
            return True
        return False

    def __InOrderTraversal(self, curr_node):
        nodeList = []
        if curr_node is not None:
            nodeList.insert(0, curr_node)
            nodeList = nodeList + self.__InOrderTraversal(curr_node.left)
            nodeList = nodeList + self.__InOrderTraversal(curr_node.right)
        return nodeList

    def getRoot(self):
        return self.root

    def __is_right_children(self, node):
        if node == node.parent.right:
            return True
        return False

    def __reassign_nodes(self, node, new_children):
        if new_children is not None:
            new_children.set_parent(node.parent)
            new_children.set_column(node.column)
        if node.parent is not None:
            #If it is the Right Children
            if self.__is_right_children(node):
                node.parent.set_right(new_children)
            else:
                #Else it is the left children
                node.parent.set_left(new_children)

    #This function traversal the tree. By default it returns an
    #In order traversal list. You can pass a function to traversal
    #The tree as needed by client code
    def traversalTree(self, traversalFunction = None, root = None):
        if(traversalFunction is None):
            #Returns a list of nodes in preOrder by default
            return self.__InOrderTraversal(self.root)
        else:
            #Returns a list of nodes in the order that the users wants to
            return traversalFunction(self.root)

    #Returns an string of all the nodes labels in the list
    #In Order Traversal
    def __str__(self):
        list = self.__InOrderTraversal(self.root)
        str = ""
        for x in list:
            str = str + " " + x.address.__str__()
        return str

def InPreOrder(curr_node):
    nodeList = []
    if curr_node is not None:
        nodeList = nodeList + InPreOrder(curr_node.left)
        nodeList.insert(0, curr_node.address)
        nodeList = nodeList + InPreOrder(curr_node.right)
    return nodeList
