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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Exception\FilterParseException;

/**
 * Common methods for filters using attributes.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait FilterAttributeTrait
{
    protected string $attribute;

    public function __toString(): string
    {
        return $this->toString();
    }

    public function getAttribute(): string
    {
        return $this->attribute;
    }

    /**
     * @api
     */
    public function setAttribute(string $attribute): static
    {
        $this->attribute = $attribute;

        return $this;
    }

    /**
     * The attribute as a filter string names it.
     *
     * @throws FilterParseException
     */
    private function attributeToString(): string
    {
        if (!Attribute::isValidDescription($this->attribute)) {
            throw new FilterParseException(sprintf(
                'The attribute "%s" has no valid filter string representation.',
                $this->attribute,
            ));
        }

        return $this->attribute;
    }
}
