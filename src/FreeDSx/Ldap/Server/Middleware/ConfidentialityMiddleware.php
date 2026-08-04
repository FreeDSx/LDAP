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

namespace FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Queue\ConnectionControl;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Config\ConfidentialityRequirement;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use FreeDSx\Ldap\ServerOptions;

/**
 * Refuses what the configured {@see ConfidentialityRequirement} will not allow over an unprotected connection.
 *
 * Placed ahead of the bind so a credential is refused before it is read, rather than after it has been compared.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ConfidentialityMiddleware implements MiddlewareInterface
{
    public function __construct(
        private ServerListenerOptionsInterface $options,
        private ConnectionControl $connection,
    ) {}

    /**
     * @throws OperationException
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        if ($this->isPermitted($context->message->getRequest())) {
            return $next->handle($context);
        }

        throw new OperationException(
            'This operation requires a confidential connection.',
            ResultCode::CONFIDENTIALITY_REQUIRED,
        );
    }

    private function isPermitted(RequestInterface $request): bool
    {
        if ($this->isConfidential()) {
            return true;
        }

        return match ($this->options->getRequireConfidentiality()) {
            ConfidentialityRequirement::None => true,
            ConfidentialityRequirement::CredentialBind => !$this->carriesCredential($request),
            ConfidentialityRequirement::AllOperations => $this->reachesConfidentiality($request),
        };
    }

    /**
     * Whether the connection cannot be read in transit.
     *
     * A unix socket qualifies, since the connection itself never traverses a network.
     */
    private function isConfidential(): bool
    {
        return $this->connection->isEncrypted()
            || $this->options->getNetworkConfig()->isUnixSocket();
    }

    /**
     * Whether the bind puts a credential on the wire.
     *
     * EXTERNAL carries none, authenticating instead from the TLS certificate already in play. Every other mechanism
     * is treated as credential-bearing, including the challenge-response ones, whose exchanges can be attacked
     * offline once captured.
     */
    private function carriesCredential(RequestInterface $request): bool
    {
        if ($request instanceof SaslBindRequest) {
            return $request->getMechanism() !== ServerOptions::SASL_EXTERNAL;
        }

        return $request instanceof SimpleBindRequest;
    }

    /**
     * Whether the request is one a plaintext client must keep, to negotiate protection or to leave.
     *
     * Without the StartTLS exemption the requirement could never be satisfied on a connection that begins in the
     * clear. Unbind and Abandon disclose nothing and carry no response.
     */
    private function reachesConfidentiality(RequestInterface $request): bool
    {
        if ($request instanceof ExtendedRequest) {
            return $request->getName() === ExtendedRequest::OID_START_TLS;
        }

        return $request instanceof UnbindRequest
            || $request instanceof AbandonRequest;
    }
}
