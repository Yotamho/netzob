from netzob.Common.Utils.Decorators import NetzobLogger, typeCheck
from netzob.Model.Vocabulary.AbstractField import AbstractField


@NetzobLogger
class FieldSplitOffset(object):

    @staticmethod
    @typeCheck(AbstractField, list)
    def split(field, offsets):
        """

        :param field:
        :param offsets:
        :return:
        """

        # Find message substrings after applying delimiter
        splitted_messages = []

        for cell in field.getValues(encoded=False, styled=False):
            splitted_messages.append(FieldSplitOffset.split_bytes_by_offsets(cell, offsets))
        print(splitted_messages)

    @staticmethod
    def split_bytes_by_offsets(bytes_, offsets):
        """

        :param bytes_:
        :param offsets:
        :return:
        """
        splitted_message = []
        splitted_message.append(bytes_[:offsets[0]])
        for i, offset in enumerate(offsets[1:]):
            splitted_message.append(bytes_[offsets[i]:offset])
            bytes_ = bytes_[offset:]
        splitted_message.append(bytes_)
        return splitted_message
