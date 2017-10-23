<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\PhpDs\Ldap\Asn1;

use PhpDs\Ldap\Asn1\Asn1;
use PhpDs\Ldap\Asn1\Type\AbstractType;
use PhpDs\Ldap\Asn1\Type\BooleanType;
use PhpDs\Ldap\Asn1\Type\EnumeratedType;
use PhpDs\Ldap\Asn1\Type\IntegerType;
use PhpDs\Ldap\Asn1\Type\NullType;
use PhpDs\Ldap\Asn1\Type\OctetStringType;
use PhpDs\Ldap\Asn1\Type\SequenceOfType;
use PhpDs\Ldap\Asn1\Type\SequenceType;
use PhpDs\Ldap\Asn1\Type\SetOfType;
use PhpDs\Ldap\Asn1\Type\SetType;
use PhpDs\Ldap\Protocol\Element\LdapDn;
use PhpDs\Ldap\Protocol\Element\LdapOid;
use PhpDs\Ldap\Protocol\Element\LdapString;
use PhpSpec\ObjectBehavior;

class Asn1Spec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(Asn1::class);
    }

    function it_should_construct_a_sequence_type()
    {
        $this::sequence(new IntegerType(1), new IntegerType(2))->shouldBeLike(new SequenceType(
            new IntegerType(1),
            new IntegerType(2)
        ));
    }

    function it_should_construct_a_boolean_type()
    {
        $this::boolean(false)->shouldBeLike(new BooleanType(false));
    }

    function it_should_construct_an_integer_type()
    {
        $this::integer(1)->shouldBeLike(new IntegerType(1));
    }

    function it_should_construct_an_enumerated_type()
    {
        $this::enumerated(1)->shouldBeLike(new EnumeratedType(1));
    }

    function it_should_construct_a_null_type()
    {
        $this::null()->shouldBeLike(new NullType());
    }

    function it_should_construct_a_sequence_of_type()
    {
        $this::sequenceOf(new IntegerType(1), new IntegerType(2))->shouldBeLike(new SequenceOfType(
            new IntegerType(1),
            new IntegerType(2)
        ));
    }

    function it_should_construct_an_ldap_dn()
    {
        $this::ldapDn('foo')->shouldBeLike(new LdapDn('foo'));
    }

    function it_should_construct_an_ldap_oid()
    {
        $this::ldapOid('foo')->shouldBeLike(new LdapOid('foo'));
    }

    function it_should_construct_an_ldap_string()
    {
        $this::ldapString('foo')->shouldBeLike(new LdapString('foo'));
    }

    function it_should_construct_a_set_type()
    {
        $this::set(new BooleanType(true), new BooleanType(false))->shouldBeLike(new SetType(
            new BooleanType(true),
            new BooleanType(false)
        ));
    }

    function it_should_construct_a_set_of_type()
    {
        $this::setOf(new BooleanType(true), new BooleanType(false))->shouldBeLike(new SetOfType(
            new BooleanType(true),
            new BooleanType(false)
        ));
    }

    function it_should_construct_an_octet_string_type()
    {
        $this::octetString('foo')->shouldBeLike(new OctetStringType('foo'));
    }

    function it_should_tag_a_type_as_context_specific()
    {
        $this::context(5, new BooleanType(true))->shouldBeLike((new BooleanType(true))->setTagNumber(5)->setTagClass(AbstractType::TAG_CLASS_CONTEXT_SPECIFIC));
    }

    function it_should_tag_a_type_as_universal()
    {
        $this::universal(6, new BooleanType(true))->shouldBeLike((new BooleanType(true))->setTagNumber(6)->setTagClass(AbstractType::TAG_CLASS_UNIVERSAL));
    }

    function it_should_tag_a_type_as_private()
    {
        $this::private(5, new BooleanType(true))->shouldBeLike((new BooleanType(true))->setTagNumber(5)->setTagClass(AbstractType::TAG_CLASS_PRIVATE));
    }
}
