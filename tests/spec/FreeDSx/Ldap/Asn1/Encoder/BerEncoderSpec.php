<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Asn1\Encoder;

use FreeDSx\Ldap\Asn1\Encoder\BerEncoder;
use FreeDSx\Ldap\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Asn1\Type\BooleanType;
use FreeDSx\Ldap\Asn1\Type\EnumeratedType;
use FreeDSx\Ldap\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Asn1\Type\IntegerType;
use FreeDSx\Ldap\Asn1\Type\NullType;
use FreeDSx\Ldap\Asn1\Type\OctetStringType;
use FreeDSx\Ldap\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\EncoderException;
use FreeDSx\Ldap\Exception\PartialPduException;
use PhpSpec\ObjectBehavior;

class BerEncoderSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(BerEncoder::class);
    }

    function it_should_implement_the_encoder_interface()
    {
        $this->shouldImplement('FreeDSx\Ldap\Asn1\Encoder\EncoderInterface');
    }

    function it_should_decode_long_definite_length()
    {
        $chars = str_pad('0', 131071, '0');

        $this->decode(hex2bin('048301ffff').$chars)->shouldBeLike(new OctetStringType($chars));
    }

    function it_should_encode_long_definite_length()
    {
        $chars = str_pad('', 131071, '0');

        $this->encode(new OctetStringType($chars))->shouldBeEqualTo(hex2bin('048301ffff').$chars);
    }

    function it_should_not_allow_long_definite_length_greater_than_or_equal_to_127()
    {
        $this->shouldThrow(EncoderException::class)->duringDecode(hex2bin('04ff'));
    }

    function it_should_decode_a_boolean_true_type()
    {
        $this->decode(hex2bin('0101FF'))->shouldBeLike(new BooleanType(true));
        $this->decode(hex2bin('0101F3'))->shouldBeLike(new BooleanType(true));
    }

    function it_should_decode_a_boolean_false_type()
    {
        $this->decode(hex2bin('010100'))->shouldBeLike(new BooleanType(false));
    }

    function it_should_encode_a_boolean_type()
    {
        $this->encode(new BooleanType(true))->shouldBeEqualTo(hex2bin('0101FF'));
        $this->encode(new BooleanType(false))->shouldBeEqualTo(hex2bin('010100'));
    }

    function it_should_decode_a_null_type()
    {
        $this->decode(hex2bin('0500'))->shouldBeLike(new NullType());
    }

    function it_should_encode_a_null_type()
    {
        $this->encode(new NullType())->shouldBeEqualTo(hex2bin('0500'));
    }

    function it_should_decode_a_zero_integer_type()
    {
        $this->decode(hex2bin('020100'))->shouldBeLike(new IntegerType(0));
    }

    function it_should_encode_a_zero_integer_type()
    {
        $this->encode(new IntegerType(0))->shouldBeEqualTo(hex2bin('020100'));
    }

    function it_should_decode_a_positive_integer_type()
    {
        $this->decode(hex2bin('020269BA'))->shouldBeLike(new IntegerType(27066));
        $this->decode(hex2bin('02020100'))->shouldBeLike(new IntegerType(256));
        $this->decode(hex2bin('020200FF'))->shouldBeLike(new IntegerType(255));
        $this->decode(hex2bin('02017F'))->shouldBeLike(new IntegerType(127));
        $this->decode(hex2bin('02020080'))->shouldBeLike(new IntegerType(128));
    }

    function it_should_encode_a_positive_integer_type()
    {
        $this->encode(new IntegerType(27066))->shouldBeEqualTo(hex2bin('020269BA'));
        $this->encode(new IntegerType(256))->shouldBeEqualTo(hex2bin('02020100'));
        $this->encode(new IntegerType(255))->shouldBeEqualTo(hex2bin('020200FF'));
        $this->encode(new IntegerType(127))->shouldBeEqualTo(hex2bin('02017F'));
        $this->encode(new IntegerType(128))->shouldBeEqualTo(hex2bin('02020080'));
    }

    function it_should_decode_a_negative_integer_type()
    {
        $this->decode(hex2bin('02029646'))->shouldBeLike(new IntegerType(-27066));
        $this->decode(hex2bin('0202FF81'))->shouldBeLike(new IntegerType(-127));
        $this->decode(hex2bin('020180'))->shouldBeLike(new IntegerType(-128));
        $this->decode(hex2bin('0202FF7F'))->shouldBeLike(new IntegerType(-129));
        $this->decode(hex2bin('0202FFFF'))->shouldBeLike(new IntegerType(-1));
    }

    function it_should_encode_a_negative_integer_type()
    {
        $this->encode(new IntegerType(-27066))->shouldBeEqualTo(hex2bin('02029646'));
        $this->encode(new IntegerType(-127))->shouldBeEqualTo(hex2bin('0202FF81'));
        $this->encode(new IntegerType(-128))->shouldBeEqualTo(hex2bin('020180'));
        $this->encode(new IntegerType(-129))->shouldBeEqualTo(hex2bin('0202FF7F'));
        $this->encode(new IntegerType(-1))->shouldBeEqualTo(hex2bin('0202FFFF'));
    }

    function it_should_decode_an_octet_string_type()
    {
        $this->decode(hex2bin('0416312e332e362e312e342e312e313436362e3230303337'))->shouldBeLike(new OctetStringType('1.3.6.1.4.1.1466.20037'));
    }

    function it_should_encode_an_octet_string()
    {
        $this->encode(new OctetStringType('1.3.6.1.4.1.1466.20037'))->shouldBeEqualTo(hex2bin('0416312e332e362e312e342e312e313436362e3230303337'));
    }

    function it_should_decode_an_enumerated_type()
    {
        $this->decode(hex2bin('0A0101'))->shouldBeLike(new EnumeratedType(1));
    }

    function it_should_encode_an_enumerated_type()
    {
        $this->encode(new EnumeratedType(1))->shouldBeEqualTo(hex2bin('0A0101'));
    }

    function it_should_decode_a_sequence_type()
    {
        $this->decode(hex2bin('30090201010201020101ff'))->shouldBeLike(new SequenceType(
            new IntegerType(1),
            new IntegerType(2),
            new BooleanType(true)
        ));
    }

    function it_should_encode_a_sequence_type()
    {
        $this->encode(new SequenceType(
            new IntegerType(1),
            new IntegerType(2),
            new BooleanType(true)
        ))->shouldBeEqualTo(hex2bin('30090201010201020101ff'));
    }

    function it_should_decode_an_unknown_type()
    {
        $incompleteType = new IncompleteType(hex2bin('01'));
        $incompleteType->setTagClass(AbstractType::TAG_CLASS_PRIVATE)->setTagNumber(7);

        $this->decode(hex2bin('c70101'))->shouldBeLike($incompleteType);
    }

    function it_should_throw_an_error_when_decoding_incorrect_length()
    {
        $this->shouldThrow(new EncoderException('The expected byte length was 4, but received 3.'))->duringDecode(hex2bin('010201'));
    }

    function it_should_throw_an_error_if_indefinite_length_encoding_is_used()
    {
        $this->shouldThrow(new EncoderException('Indefinite length encoding is not supported.'))->duringDecode(hex2bin('0180010000'));
    }

    function it_should_save_trailing_data()
    {
        $type = (new BooleanType(true))->setTrailingData(0x00);
        $this->decode(hex2bin('0101FF00'))->shouldBeLike($type);
    }

    function it_should_throw_a_partial_PDU_exception_with_only_a_byte_of_data()
    {
        $this->shouldThrow(PartialPduException::class)->duringDecode(hex2bin('30'));
    }

    function it_should_throw_a_partial_PDU_exception_without_enough_data_to_decode_length()
    {
        $this->shouldThrow(new PartialPduException('Not enough data to decode the length.'))->duringDecode(hex2bin('048301ff'));
        $this->shouldNotThrow(PartialPduException::class)->during('decode', [hex2bin('30840000003702010264840000002e0426434e3d436861642c434e3d55736572732c44433d6c646170746f6f6c732c44433d6c6f63616c308400000000')]);
    }

    function it_should_detect_a_context_specific_tag_type_correctly()
    {
        $this->decode(hex2bin('800001'))->getTagClass()->shouldBeEqualTo(AbstractType::TAG_CLASS_CONTEXT_SPECIFIC);
    }

    function it_should_detect_an_application_tag_correctly()
    {
        $this->decode(hex2bin('400001'))->getTagClass()->shouldBeEqualTo(AbstractType::TAG_CLASS_APPLICATION);
    }

    function it_should_detect_a_private_tag_correctly()
    {
        $this->decode(hex2bin('c00001'))->getTagClass()->shouldBeEqualTo(AbstractType::TAG_CLASS_PRIVATE);
    }

    function it_should_detect_a_universal_tag_correctly()
    {
        $this->decode(hex2bin('010101'))->getTagClass()->shouldBeEqualTo(AbstractType::TAG_CLASS_UNIVERSAL);
    }

    function it_should_complete_an_incomplete_type()
    {
        $this->complete((new IncompleteType(hex2bin('FF')))->setTagNumber(5), AbstractType::TAG_TYPE_BOOLEAN)
            ->shouldBeLike((new BooleanType(true))->setTagNumber(5));
    }
}
