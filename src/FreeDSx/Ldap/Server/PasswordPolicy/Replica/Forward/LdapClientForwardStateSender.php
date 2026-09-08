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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward;

use FreeDSx\Ldap\Exception\ForwardStateException;
use FreeDSx\Ldap\Exception\ForwardStateRejectedException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Sync\Consumer\PrimaryConnectionFactory;
use Throwable;

use function sprintf;

/**
 * Sends password-policy forward requests to the primary over a dedicated client using the replica's sync identity,
 * reconnecting on the next attempt after a transport failure.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapClientForwardStateSender implements ForwardStateSenderInterface
{
    private ?LdapClient $client = null;

    public function __construct(private readonly PrimaryConnectionFactory $connectionFactory) {}

    /**
     * @throws ForwardStateException
     */
    public function send(ForwardPasswordPolicyStateRequest $request): void
    {
        $this->assertAccepted($this->exchange($request));
    }

    /**
     * @throws ForwardStateRejectedException when the primary answered with a result code (the connection stays open).
     * @throws ForwardStateException on a transport failure (the connection is dropped so the next send reconnects).
     */
    private function exchange(ForwardPasswordPolicyStateRequest $request): object
    {
        try {
            return $this->connect()
                ->sendAndReceive($request)
                ->getResponse();
        } catch (OperationException $e) {
            throw new ForwardStateRejectedException(
                sprintf(
                    'The primary rejected the password-policy forward with result code %d.',
                    $e->getCode(),
                ),
                $e->getCode(),
                $e,
            );
        } catch (Throwable $e) {
            $this->reset();

            throw new ForwardStateException(
                'Failed to deliver the password-policy forward to the primary.',
                $e->getCode(),
                $e,
            );
        }
    }

    private function connect(): LdapClient
    {
        return $this->client ??= $this->connectionFactory->connectLdapClient();
    }

    /**
     * @throws ForwardStateException when the primary rejected the forward (the connection stays open for a retry).
     */
    private function assertAccepted(object $response): void
    {
        if (!$response instanceof ExtendedResponse) {
            throw new ForwardStateException('The primary returned an unexpected response to the password-policy forward.');
        }
        if ($response->getResultCode() !== ResultCode::SUCCESS) {
            throw new ForwardStateRejectedException(sprintf(
                'The primary rejected the password-policy forward with result code %d.',
                $response->getResultCode(),
            ));
        }
    }

    private function reset(): void
    {
        $this->client?->disconnect();
        $this->client = null;
    }
}
