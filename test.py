import base64
import json

from OpenSSL import crypto
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.x509 import BasicConstraints

from avsniper.libs.binary_tree import BinarySearchTree
from avsniper.libs.ca import CA
from avsniper.libs.pyinstaller import PyInstArchive
from avsniper.util.tools import Tools

with open('/tmp/pyrunner_4.0.0.0_zt_9.10.100.105.exe', 'rb') as pe:
    f_data = bytearray(pe.read())

pyinst = PyInstArchive(f_data)
tree = BinarySearchTree()
for f in pyinst.tocList:
    print(f.position)
    if f.cmprsdDataSize > 0:
        tree.insert(f.position, f.cmprsdDataSize)

#for i in [10,11,7,9,15,8,12]:
#    print(i)
#    tree.insert(i, 1)


print("jfkldsjlfksdjlsda\n\n")
tree.build()

print(tree.root)

for i in range(1, 5):
    if (t := tree.get_next()) is not None:
        print(t, t.get_min(), t.get_max())

#print(tree.getRoot().getAddr())
#print(tree.__str__())
#print("Tree:\n\n")
#print(tree.draw_tree())

#tree.delete(12)
#print(tree.draw_tree())
