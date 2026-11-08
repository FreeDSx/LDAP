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

namespace FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Search\Filter\FilterInterface;

/**
 * Represents an assertion control. RFC 4528.
 *
 * The operation proceeds only if the filter matches the target entry.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class AssertionControl extends Control
{
    public function __construct(
        private FilterInterface $filter,
        bool $criticality = true,
    ) {
        parent::__construct(
            self::OID_ASSERTION,
            $criticality,
        );
    }

    public function getFilter(): FilterInterface
    {
        return $this->filter;
    }

    public function setFilter(FilterInterface $filter): self
    {
        $this->filter = $filter;

        return $this;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = $this->filter;

        return parent::toAsn1();
    }
}
