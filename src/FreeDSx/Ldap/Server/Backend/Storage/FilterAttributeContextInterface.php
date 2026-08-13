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

namespace FreeDSx\Ldap\Server\Backend\Storage;

/**
 * The schema derived facts a filter translator needs, without handing it the schema itself.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface FilterAttributeContextInterface
{
    /**
     * Whether the attribute orders numerically, or null when it cannot be resolved.
     */
    public function isIntegerOrdered(string $attribute): ?bool;

    /**
     * Whether the attribute matches without regard to case, or null when it cannot be resolved.
     */
    public function isCaseInsensitive(string $attribute): ?bool;

    /**
     * How faithfully SQL alone can answer an assertion on the attribute.
     */
    public function filterSupport(string $attribute): AttributeFilterSupport;

    /**
     * Whether a value conforms to the attribute's syntax (false makes the item Undefined per RFC 4511 4.5.1.7).
     */
    public function assertionValueConforms(
        string $attribute,
        string $value,
    ): bool;

    /**
     * Whether the attribute defines a SUBSTR rule (false makes a substring item Undefined per RFC 4511 4.5.1.7).
     */
    public function hasSubstringRule(string $attribute): bool;
}
