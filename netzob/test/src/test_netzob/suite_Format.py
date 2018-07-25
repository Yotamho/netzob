import unittest

# import os, sys
# sys.path.insert('/root/IdeaProjects/netzob/netzob/src')

from netzob.Import.PCAPImporter.all import PCAPImporter
from netzob.Inference.Vocabulary.CorrelationFinder import CorrelationFinder
from netzob.Inference.Vocabulary.EntropyMeasurement import EntropyMeasurement
from netzob.Inference.Vocabulary.FormatOperations.FieldSplitOffset import FieldSplitOffset
from netzob.Inference.Vocabulary.RelationFinder import RelationFinder
from netzob.Inference.Vocabulary.all import Format
from netzob.Model.Grammar.Automata import Automata
from netzob.Model.Vocabulary.AbstractField import AbstractField
from netzob.Model.Vocabulary.Domain.Variables.Leafs.Size import Size
from netzob.Model.Vocabulary.Session import Session
from netzob.Model.Vocabulary.Symbol import Symbol
from netzob.Model.Vocabulary.Types.Raw import Raw


class TestFormat(unittest.TestCase):

    def test_split_bytes_by_offsets(self):
        self.assertEqual(FieldSplitOffset.split_bytes_by_offsets(b'fgsdfgsdfg', [1, 2, 5]), ["f", "g", "sdf", "dfg"])

    @staticmethod
    def test_split_offset():
        BPF_FILTER = "!(arp) and !(len == 96)"
        messages = PCAPImporter.readFile("/home/research/Downloads/hunter_no_vlan.pcap", nbPackets=100,
                                         bpfFilter=BPF_FILTER).values()

        bytes_entropy = [byte_entropy for byte_entropy in EntropyMeasurement.measure_entropy(messages)]
        print(bytes_entropy)

        symbol = Symbol(messages=messages)

        Format.splitStatic(symbol)

        Format.splitOffset(symbol, [3, 4, 5])

        clusters = Format.clusterByKeyField(symbol, symbol.fields[1])
        for key, value in clusters.items():
            print(value)
        new_symbol = list(clusters.items())[-1][1]
        print(new_symbol)

        rels = CorrelationFinder.find(new_symbol, minMic=0.7)
        for rel in rels:
            print("  " + rel["relation_type"] + ", between '" + rel["x_attribute"] + "' of:")
            print("    " + str('-'.join([f.name for f in rel["x_fields"]])))
            p = [v.getValues()[:] for v in rel["x_fields"]]
            print("    " + str(p))
            print("  " + "and '" + rel["y_attribute"] + "' of:")
            print("    " + str('-'.join([f.name for f in rel["y_fields"]])))
            p = [v.getValues()[:] for v in rel["y_fields"]]
            print("    " + str(p))
            print("  by MIC: {} and PEARSON: {}".format(rel["mic"], rel["pearson"]))

        rels = RelationFinder.findOnSymbol(new_symbol)
        for rel in rels:
            print("  " + rel["relation_type"] + ", between '" + rel["x_attribute"] + "' of:")
            print("    " + str('-'.join([f.name for f in rel["x_fields"]])))
            p = [v.getValues()[:] for v in rel["x_fields"]]
            print("    " + str(p))
            print("  " + "and '" + rel["y_attribute"] + "' of:")
            print("    " + str('-'.join([f.name for f in rel["y_fields"]])))
            p = [v.getValues()[:] for v in rel["y_fields"]]
            print("    " + str(p))
            rel["x_fields"][0].domain = Size(rel["y_fields"], factor=1/8.0)
        print(new_symbol.fields[2].domain)

        message_to_verify = messages[1]
        print(AbstractField.abstract(message_to_verify.data, list(clusters.values())))

        session = Session(messages)
        abstractSession = session.abstract(list(clusters.values()))
        automata = Automata.generateChainedStatesAutomata(abstractSession, list(clusters.values()))
        dotcode = automata.generateDotCode()
        print(dotcode)


    @staticmethod
    def test_split_delimiter():
        BPF_FILTER = "!(arp) and !(len == 96)"

        messages = PCAPImporter.readFile("/home/research/Downloads/hunter_no_vlan.pcap", nbPackets=10,
                                         bpfFilter=BPF_FILTER).values()
        symbol = Symbol(messages=messages)
        Format.splitDelimiter(symbol.fields[0], Raw(b'\05'))

    @staticmethod
    def test_split_static():
        BPF_FILTER = "!(arp) and !(len == 96)"

        messages = PCAPImporter.readFile("/home/research/Downloads/hunter_no_vlan.pcap", nbPackets=10,
                                         bpfFilter=BPF_FILTER).values()
        symbol = Symbol(messages=messages)
        Format.splitStatic(symbol)
        return symbol

    # @staticmethod
    # def test_message_parser():
    #     msg = b'\x07\xbe[\x05\x08,3c\x80\x00\x07\x00d'
    #     splitted_msg = FieldSplitOffset.split_bytes_by_offsets(msg, [4])
    #     f0 = Field(domain=Raw(splitted_msg[0]))
    #     f1 = Field(domain=Raw(splitted_msg[1]))
    #     print(f0)

TestFormat.test_split_offset()