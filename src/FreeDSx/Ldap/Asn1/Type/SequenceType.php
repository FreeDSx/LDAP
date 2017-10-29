<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Asn1\Type;

/**
 * Represents a Sequence type.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SequenceType extends AbstractType implements ConstructedTypeInterface, \Countable, \IteratorAggregate
{
    use ConstructedTypeTrait;

    /**
     * @var int
     */
    protected $tagNumber = self::TAG_TYPE_SEQUENCE;
}
