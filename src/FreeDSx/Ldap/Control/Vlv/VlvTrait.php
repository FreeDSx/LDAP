<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Control\Vlv;

/**
 * Some common VLV methods/properties.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait VlvTrait
{
    private ?int $count;

    private ?string $contextId;

    private ?int $offset;

    public function getContextId(): ?string
    {
        return $this->contextId;
    }

    public function getOffset(): ?int
    {
        return $this->offset;
    }

    public function getCount(): ?int
    {
        return $this->count;
    }
}
