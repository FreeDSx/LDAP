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

namespace FreeDSx\Ldap\Search\Filter;

/**
 * Common methods for filters using attributes.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait FilterAttributeTrait
{
    protected string $attribute;

    public function getAttribute(): string
    {
        return $this->attribute;
    }

    public function setAttribute(string $attribute): static
    {
        $this->attribute = $attribute;

        return $this;
    }

    public function __toString(): string
    {
        return $this->toString();
    }
}
