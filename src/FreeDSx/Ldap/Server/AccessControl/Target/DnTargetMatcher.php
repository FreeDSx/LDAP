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

namespace FreeDSx\Ldap\Server\AccessControl\Target;

use FreeDSx\Ldap\Entry\Dn;

/**
 * Matches a specific target DN (case-insensitive).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class DnTargetMatcher implements TargetMatcherInterface
{
    private readonly string $normalizedDn;

    public function __construct(string $dn)
    {
        $this->normalizedDn = (new Dn($dn))->normalizedString();
    }

    public function matches(Dn $dn): bool
    {
        return $dn->normalizedString() === $this->normalizedDn;
    }
}
