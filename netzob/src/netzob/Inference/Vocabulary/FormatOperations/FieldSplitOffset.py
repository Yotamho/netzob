import itertools
from netzob.Common.Utils.Decorators import NetzobLogger, typeCheck
from netzob.Model.Vocabulary.AbstractField import AbstractField
from netzob.Model.Vocabulary.Domain.DomainFactory import DomainFactory
from netzob.Model.Vocabulary.Field import Field
from netzob.Model.Vocabulary.Types.BitArray import BitArray
from netzob.Model.Vocabulary.Types.HexaString import HexaString
from netzob.Model.Vocabulary.Types.Raw import Raw
from netzob.Model.Vocabulary.Types.TypeConverter import TypeConverter


@NetzobLogger
class FieldSplitOffset(object):

    @staticmethod
    @typeCheck(AbstractField, list)
    def split(field: Field, offsets):
        """

        :param field:
        :param offsets:
        :return:
        """

        # Find message substrings after applying delimiter
        splitted_messages = []

        for cell in field.getValues(encoded=False, styled=False):
            splitted_messages.append(FieldSplitOffset.split_bytes_by_offsets(cell, offsets))
        splitted_fields = list(itertools.zip_longest(*splitted_messages))
        new_fields = []
        for (i, val) in enumerate(splitted_fields):
            fName = "Field-{0}".format(i)
            fDomain = DomainFactory.normalizeDomain([
                Raw(TypeConverter.convert(v, HexaString, BitArray))
                for v in set(val)
            ])
            new_fields.append(Field(domain=fDomain, name=fName))

        # attach encoding functions
        for newField in new_fields:
            newField.encodingFunctions = list(field.encodingFunctions.values())

        field.fields = new_fields

    @staticmethod
    def split_bytes_by_offsets(bytes_, offsets):
        """

        :param bytes_:
        :param offsets:
        :return:
        """
        splitted_message = []
        splitted_message.append(TypeConverter.convert(bytes_[:offsets[0]], Raw, HexaString))
        bytes_ = bytes_[offsets[0]:]
        for i, start_offset in enumerate(offsets[:-1]):
            splitted_message.append(TypeConverter.convert(bytes_[:offsets[i+1]-start_offset], Raw, HexaString))
            bytes_ = bytes_[offsets[i+1]-start_offset:]
        splitted_message.append(TypeConverter.convert(bytes_, Raw, HexaString))
        return splitted_message
