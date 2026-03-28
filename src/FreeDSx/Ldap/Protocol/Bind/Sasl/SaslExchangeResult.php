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
use FreeDSx\Sasl\SaslContext;

/**
 * Aggregates the outcome of a SASL challenge-response exchange.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SaslExchangeResult
{
    public function __construct(
        private readonly SaslContext $context,
        private readonly LdapMessageRequest $lastMessage,
        private readonly ?string $usernameCredentials,
    ) {
    }

    public function getContext(): SaslContext
    {
        return $this->context;
    }

    public function getLastMessage(): LdapMessageRequest
    {
        return $this->lastMessage;
    }

    public function getUsernameCredentials(): ?string
    {
        return $this->usernameCredentials;
    }
}
