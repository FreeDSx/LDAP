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

namespace FreeDSx\Ldap\Server\AccessControl\Rule;

/**
 * The direction a relocation rule applies to, relative to the container it targets.
 *
 * A request is always Out or In, a rule may be Both.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum RelocationAccess
{
    /**
     * Entries leaving the container.
     */
    case Out;

    /**
     * Entries arriving in the container.
     */
    case In;

    case Both;

    /**
     * Whether a rule with this scope applies to the requested direction.
     */
    public function includes(self $requested): bool
    {
        return $this === self::Both
            || $this === $requested;
    }
}
