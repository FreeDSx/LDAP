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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter;

/**
 * An immutable value object holding a translated SQL filter fragment and its bound parameters.
 *
 * @see FilterTranslatorInterface
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SqlFilterResult
{
    /**
     * @param list<string> $params
     * @param list<string> $referencedAttributes Attributes whose absence makes the filter undefined under RFC 4511
     */
    public function __construct(
        public readonly string $sql,
        public readonly array $params,
        public readonly bool $isExact = true,
        public readonly array $referencedAttributes = [],
    ) {
    }
}
