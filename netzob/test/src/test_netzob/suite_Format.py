import unittest
from netzob.Import.PCAPImporter.all import PCAPImporter
from netzob.Inference.Vocabulary.FormatOperations.FieldSplitOffset import FieldSplitOffset
from netzob.Inference.Vocabulary.all import Format
from netzob.Model.Vocabulary.Symbol import Symbol


class TestFormat(unittest.TestCase):

    def test_split_bytes_by_offsets(self):
        self.assertEqual(FieldSplitOffset.split_bytes_by_offsets(b'fgsdfgsdfg', [1, 2, 5]), ["f", "g", "sdf", "dfg"])

    def test_split_offset(self):
        BPF_FILTER = "!(arp) and !(len == 96)"

        messages = PCAPImporter.readFile("/home/research/Downloads/hunter_no_vlan.pcap", nbPackets=10,
                                         bpfFilter=BPF_FILTER).values()
        symbol = Symbol(messages=messages)
        Format.splitOffset(symbol.fields[0], [4])
