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

use FreeDSx\Ldap\Exception\InvalidDnSyntaxException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\MatchedDnAccessFilterTrait;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\FailedOperationResult;

/**
 * The single sink: drains the response stream to the queue, rendering any thrown OperationException as its response.
 *
 * A streaming handler runs during the drain, so mid-stream failures are answered here too (a partial stream is followed by its error terminal).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ResponseWriterMiddleware implements MiddlewareInterface
{
    use MatchedDnAccessFilterTrait;

    public function __construct(
        private ResponseWriter $writer,
        private LdapBackendInterface $backend,
        private AccessControlInterface $accessControl,
        private ResponseFactory $responseFactory = new ResponseFactory(),
    ) {}

    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        $messageId = $context->message->getMessageId();

        try {
            $outcome = $this->writer->write(
                $next->handle($context),
                $messageId,
            );
        } catch (OperationException $e) {
            $outcome = $this->writer->write(
                $this->errorStream($context, $e),
                $messageId,
            );
        } catch (InvalidDnSyntaxException $e) {
            // A DN is only parsed once something needs its pieces, which is well past the decode. Answering it here
            // keeps a malformed one from ending the session on its way out as an unhandled failure.
            $outcome = $this->writer->write(
                $this->errorStream(
                    $context,
                    new OperationException(
                        $e->getMessage(),
                        ResultCode::INVALID_DN_SYNTAX,
                        $e,
                    ),
                ),
                $messageId,
            );
        }

        return ResponseStream::resolved($outcome);
    }

    private function errorStream(
        ServerRequestContext $context,
        OperationException $exception,
    ): ResponseStream {
        return ResponseStream::of(
            [$this->responseFactory->getStandardResponse(
                $context->message,
                $exception->getCode(),
                $exception->getMessage(),
                $this->filterMatchedDn(
                    $exception->getMatchedDn(),
                    $context->tokenOrFail(),
                    $this->backend,
                    $this->accessControl,
                ),
            )],
            new FailedOperationResult(
                $context->message,
                $exception,
            ),
        );
    }
}
