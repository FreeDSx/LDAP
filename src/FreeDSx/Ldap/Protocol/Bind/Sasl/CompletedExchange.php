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
 * What the challenge-response loop leaves behind once the mechanism reports completion.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class CompletedExchange
{
    /**
     * @param ?string $usernameCredentials The first credentials seen, which is where a username is read from.
     * @param ?string $serverFinal Data the mechanism produced on its last step, for the success response to carry.
     */
    public function __construct(
        public SaslContext $context,
        public ?string $usernameCredentials,
        public ?string $serverFinal,
    ) {}
}
