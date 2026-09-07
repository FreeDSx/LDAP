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

namespace FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\SaslIdentity;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Sasl\Mechanism\MechanismName;
use SensitiveParameter;

/**
 * Binds the per-connection upstream client and represents that identity for the proxied session.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ProxyAuthenticator implements PasswordAuthenticatableInterface
{
    public function __construct(
        private LdapClient $client,
        private bool $useStartTls = false,
    ) {}

    public function authenticate(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): AuthenticatedTokenInterface {
        try {
            // Re-issuing it on a connection already upgraded is an operations error the upstream answers by hanging up.
            if ($this->useStartTls && !$this->client->isEncrypted()) {
                $this->client->startTls();
            }

            $this->client->bind(
                $name,
                $password,
            );
        } catch (BindException $e) {
            throw new OperationException(
                $e->getMessage(),
                $e->getCode(),
            );
        } catch (ConnectionException) {
            throw new OperationException(
                'The upstream LDAP server is unavailable.',
                ResultCode::UNAVAILABLE,
            );
        }

        return BindToken::fromDn($name);
    }

    /**
     * SASL bind is not proxied; returns null so SASL mechanisms reject.
     */
    public function getSaslIdentity(
        string $username,
        MechanismName $mechanism,
    ): ?SaslIdentity {
        return null;
    }
}
