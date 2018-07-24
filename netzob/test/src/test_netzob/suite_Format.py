import unittest
from netzob.Import.PCAPImporter.all import PCAPImporter
from netzob.Inference.Vocabulary.FormatOperations.FieldSplitOffset import FieldSplitOffset
from netzob.Inference.Vocabulary.all import Format
from netzob.Model.Vocabulary.Field import Field
from netzob.Model.Vocabulary.Symbol import Symbol
from netzob.Model.Vocabulary.Types.Raw import Raw


class TestFormat(unittest.TestCase):

    def test_split_bytes_by_offsets(self):
        self.assertEqual(FieldSplitOffset.split_bytes_by_offsets(b'fgsdfgsdfg', [1, 2, 5]), ["f", "g", "sdf", "dfg"])

    @staticmethod
    def test_split_offset():
        BPF_FILTER = "!(arp) and !(len == 96)"

        messages = PCAPImporter.readFile("/home/research/Downloads/hunter_no_vlan.pcap", nbPackets=500,
                                         bpfFilter=BPF_FILTER).values()
        symbol = Symbol(messages=messages)
        Format.splitOffset(symbol.fields[0], [3, 4])
        # Format.clusterByKeyField(symbol.fields[0], symbol.fields[0].fields[1])
        print(symbol)

    @staticmethod
    def test_split_delimiter():
        BPF_FILTER = "!(arp) and !(len == 96)"

        messages = PCAPImporter.readFile("/home/research/Downloads/hunter_no_vlan.pcap", nbPackets=10,
                                         bpfFilter=BPF_FILTER).values()
        symbol = Symbol(messages=messages)
        Format.splitDelimiter(symbol.fields[0], Raw(b'\05'))
        print(symbol)

    # @staticmethod
    # def test_message_parser():
    #     msg = b'\x07\xbe[\x05\x08,3c\x80\x00\x07\x00d'
    #     splitted_msg = FieldSplitOffset.split_bytes_by_offsets(msg, [4])
    #     f0 = Field(domain=Raw(splitted_msg[0]))
    #     f1 = Field(domain=Raw(splitted_msg[1]))
    #     print(f0)

TestFormat.test_split_offset()
# TestFormat.test_split_delimiter()
# TestFormat.test_message_parser()