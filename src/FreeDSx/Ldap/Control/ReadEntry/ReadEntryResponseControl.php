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

use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;

/**
 * Shared Pre-Read / Post-Read response control. RFC 4527.
 *
 * Carries the entry state as a SearchResultEntry.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
abstract class ReadEntryResponseControl extends Control
{
    public function __construct(private readonly Entry $entry)
    {
        parent::__construct(static::oid());
    }

    public function getEntry(): Entry
    {
        return $this->entry;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = new SearchResultEntry($this->entry);

        return parent::toAsn1();
    }

    /**
     * The control OID for this read-entry variant (pre-read or post-read).
     */
    abstract protected static function oid(): string;
}
