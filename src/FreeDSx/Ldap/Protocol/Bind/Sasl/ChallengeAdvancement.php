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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl;

use FreeDSx\Sasl\SaslContext;

/**
 * Bundles the outcome of a single challenge advancement step.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ChallengeAdvancement
{
    public function __construct(
        public readonly SaslContext $context,
        public readonly bool $complete,
    ) {
    }
}
