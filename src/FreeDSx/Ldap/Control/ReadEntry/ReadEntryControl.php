<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Control\ReadEntry;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceOfType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * Shared Pre-Read / Post-Read request control. RFC 4527.
 *
 * Carries the attribute selection to return for the entry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
abstract class ReadEntryControl extends Control
{
    /**
     * @var string[]
     */
    private array $attributes;

    public function __construct(string ...$attributes)
    {
        $this->attributes = $attributes;
        parent::__construct(static::oid());
    }

    /**
     * @return string[]
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    public function toAsn1(): SequenceType
    {
        $attributes = [];
        foreach ($this->attributes as $attribute) {
            $attributes[] = Asn1::octetString($attribute);
        }
        $this->controlValue = SequenceOfType::fromChildren($attributes);

        return parent::toAsn1();
    }

    /**
     * {@inheritDoc}
     *
     * @param AbstractType<mixed> $type
     */
    public static function fromAsn1(AbstractType $type): static
    {
        $selection = self::decodeEncodedValue($type);

        if (!$selection instanceof SequenceType) {
            throw new ProtocolException('A read-entry control value must be a sequence of attribute names.');
        }

        $attributes = [];
        foreach ($selection->getChildren() as $child) {
            if (!$child instanceof OctetStringType) {
                throw new ProtocolException('A read-entry attribute selection must contain octet string values.');
            }
            $attributes[] = $child->getValue();
        }

        return self::mergeControlData(
            new static(...$attributes),
            $type,
        );
    }

    /**
     * The control OID for this read-entry variant (pre-read or post-read).
     */
    abstract protected static function oid(): string;
}
