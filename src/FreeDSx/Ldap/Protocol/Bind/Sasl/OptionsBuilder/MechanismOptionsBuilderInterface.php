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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder;

/**
 * Builds the options array passed to a SASL mechanism's challenge() call for a specific mechanism.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface MechanismOptionsBuilderInterface
{
    /**
     * Build the options for the next challenge() call.
     *
     * @return array<string, mixed>
     */
    public function buildOptions(
        ?string $received,
        string $mechanism,
    ): array;

    /**
     * Whether this builder handles the given mechanism name.
     */
    public function supports(string $mechanism): bool;
}
