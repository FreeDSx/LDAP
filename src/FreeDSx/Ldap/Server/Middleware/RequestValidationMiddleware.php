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

use FreeDSx\Ldap\Exception\RequestValidationException;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;

use function sprintf;

/**
 * Rejects a message whose ID is zero or in use by an operation still being served (RFC 4511 §4.1.1.1).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RequestValidationMiddleware implements MiddlewareInterface
{
    /**
     * Operations still being served, keyed by ID so a lookup does not scan.
     *
     * @var array<int, true>
     */
    private array $outstanding = [];

    /**
     * @throws RequestValidationException
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        $messageId = $context->message->getMessageId();

        if ($messageId === 0) {
            throw new RequestValidationException('The message ID 0 cannot be used in a client request.');
        }

        // RFC 4511 §4.1.1.1 forbids only an ID in use by an operation still being served.
        if (isset($this->outstanding[$messageId])) {
            throw new RequestValidationException(sprintf('The message ID %s is not valid.', $messageId));
        }

        $this->outstanding[$messageId] = true;

        try {
            // The response writer sits below this, so the operation is answered by the time the call returns.
            return $next->handle($context);
        } finally {
            unset($this->outstanding[$messageId]);
        }
    }
}
