<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Asn1\Type;

use FreeDSx\Ldap\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Asn1\Type\ConstructedTypeInterface;
use FreeDSx\Ldap\Asn1\Type\IntegerType;
use FreeDSx\Ldap\Asn1\Type\OctetStringType;
use FreeDSx\Ldap\Asn1\Type\SetOfType;
use PhpSpec\ObjectBehavior;

class SetOfTypeSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new IntegerType(1), new OctetStringType('foo'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SetOfType::class);
    }

    function it_should_implement_constructed_type_interface()
    {
        $this->shouldImplement(ConstructedTypeInterface::class);
    }

    function it_should_implement_countable()
    {
        $this->shouldImplement('\Countable');
    }

    function it_should_set_children()
    {
        $this->setChildren(new IntegerType(1), new IntegerType(2));

        $this->getChildren()->shouldBeLike([
            new IntegerType(1),
            new IntegerType(2)
        ]);
    }

    function it_should_add_a_child()
    {
        $child = new IntegerType(4);
        $this->addChild($child);

        $this->getChildren()->shouldContain($child);
    }

    function it_should_check_if_a_child_exists()
    {
        $this->hasChild(0)->shouldBeEqualTo(true);
        $this->hasChild(3)->shouldBeEqualTo(false);
    }

    function it_should_get_all_children()
    {
        $this->getChildren()->shouldBeLike([
            new IntegerType(1),
            new OctetStringType('foo')
        ]);
    }

    function it_should_get_a_child_if_it_exists()
    {
        $this->getChild(0)->shouldBeAnInstanceOf(IntegerType::class);
    }

    function it_should_be_null_when_getting_a_child_that_does_not_exist()
    {
        $this->getChild(9)->shouldBeNull();
    }

    function it_should_have_a_default_tag_type()
    {
        $this->getTagNumber()->shouldBeEqualTo(AbstractType::TAG_TYPE_SET);
    }

    function it_should_get_a_count()
    {
        $this->count()->shouldBeEqualTo(2);
    }
}
