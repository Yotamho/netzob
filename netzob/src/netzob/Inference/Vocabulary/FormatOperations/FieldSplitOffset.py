import itertools
from netzob.Common.Utils.Decorators import NetzobLogger, typeCheck
from netzob.Model.Vocabulary.AbstractField import AbstractField
from netzob.Model.Vocabulary.Domain.DomainFactory import DomainFactory
from netzob.Model.Vocabulary.Field import Field
from netzob.Model.Vocabulary.Types.Raw import Raw


@NetzobLogger
class FieldSplitOffset(object):

    @staticmethod
    @typeCheck(AbstractField, list)
    def split(field: Field, offsets):
        """

        FIXME works only for separating by 2 offsets, otherwise will raise error when parsed by MessageParser.
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
        i_field = -1
        for i in range(len(splitted_fields)):
            i_field += 1

            field_domain = list()

            # temporary set that hosts all the observed values to prevent useless duplicate ones
            observed_values = set()
            has_inserted_empty_value = False

            is_empty_field = True  # To avoid adding an empty field
            for v in splitted_fields[i]:
                if v != "" and v is not None:
                    is_empty_field = False

                    if v not in observed_values:
                        field_domain.append(Raw(v))
                        observed_values.add(v)
                else:
                    if not has_inserted_empty_value:
                        field_domain.append(Raw(nbBytes=0))
                        has_inserted_empty_value = True

            if not is_empty_field:
                new_field = Field(
                    domain=DomainFactory.normalizeDomain(field_domain),
                    name="Field-" + str(i_field))
                new_field.encodingFunctions = list(
                    field.encodingFunctions.values())
                new_fields.append(new_field)
                i_field += 1

        # Reset the field
        from netzob.Inference.Vocabulary.Format import Format
        Format.resetFormat(field)

        # Create a field for each entry
        field.fields = new_fields

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
