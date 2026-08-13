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
 * A filter asserting one whole value against an attribute type.
 */
interface AttributeValueAssertionInterface extends FilterAttributeInterface
{
    /**
     * The attribute type asserted against, which is always named for these filters.
     */
    public function getAttribute(): string;

    /**
     * The value being asserted.
     */
    public function getValue(): string;
}
