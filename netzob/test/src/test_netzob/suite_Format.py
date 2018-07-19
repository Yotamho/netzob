# from netzob.all import *

import os, sys

sys.path.insert(0, os.path.abspath('/home/research/netzob-yotam/netzob/src'))
from netzob.Inference.Vocabulary.FormatOperations.FieldSplitOffset import FieldSplitOffset
from netzob.Import.PCAPImporter import PCAPImporter

BPF_FILTER = "!(arp) and !(len == 96)"

# messages = PCAPImporter.readFile("/home/research/Downloads/hunter_no_vlan.pcap", nbPackets=500,
#                                  bpfFilter=BPF_FILTER).values()
#
# symbol = Symbol(messages=messages)
print(FieldSplitOffset.split_bytes_by_offsets(b'fgsdfgsdfg', [1, 2, 5]))
# Format.splitDelimiter(symbol.fields[0], Raw(value=b'\x05'))
# print(symbol)
