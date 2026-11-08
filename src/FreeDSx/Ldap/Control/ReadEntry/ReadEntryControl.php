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
use FreeDSx\Asn1\Type\SequenceOfType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;

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
     * The control OID for this read-entry variant (pre-read or post-read).
     */
    abstract protected static function oid(): string;
}
