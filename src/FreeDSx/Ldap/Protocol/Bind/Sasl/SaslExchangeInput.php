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

use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Sasl\Challenge\ChallengeInterface;

/**
 * Bundles the per-invocation parameters for SaslExchange::run().
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SaslExchangeInput
{
    public function __construct(
        private readonly ChallengeInterface $challenge,
        private readonly string $mechName,
        private readonly LdapMessageRequest $initialMessage,
        private readonly ?string $initialCredentials,
    ) {
    }

    public function getChallenge(): ChallengeInterface
    {
        return $this->challenge;
    }

    public function getMechName(): string
    {
        return $this->mechName;
    }

    public function getInitialMessage(): LdapMessageRequest
    {
        return $this->initialMessage;
    }

    public function getInitialCredentials(): ?string
    {
        return $this->initialCredentials;
    }
}
