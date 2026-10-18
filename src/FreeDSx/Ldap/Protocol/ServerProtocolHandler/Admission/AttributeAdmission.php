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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler\Admission;

use FreeDSx\Ldap\Server\AccessControl\Read\ReadVerdict;

/**
 * What one search request does with an attribute description wherever an entry holds it.
 *
 * @internal
 */
final readonly class AttributeAdmission
{
    /**
     * @param string $name The lowercased base type.
     * @param bool $returned Whether the request selects it.
     * @param bool $concernsFilter Whether withholding it can change whether the entry matches.
     */
    public function __construct(
        public string $name,
        public bool $returned,
        public ReadVerdict $read,
        public bool $concernsFilter,
    ) {}
}
