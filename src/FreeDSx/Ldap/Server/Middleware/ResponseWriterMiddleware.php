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

use FreeDSx\Ldap\Exception\AnswerableExceptionInterface;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\UnrecoverableExceptionInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\MatchedDnAccessFilterTrait;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\FailedOperationResult;
use Throwable;

/**
 * The single sink: drains the response stream to the queue, rendering any thrown failure as its response.
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
        private ReadBackendInterface $backend,
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
        } catch (Throwable $e) {
            $failure = $this->answerFor($e);

            if ($failure === null) {
                throw $e;
            }

            $outcome = $this->writer->write(
                $this->errorStream($context, $failure),
                $messageId,
            );
        }

        return ResponseStream::resolved($outcome);
    }

    /**
     * The result to answer a thrown failure with, or null when it has to end the session instead.
     */
    private function answerFor(Throwable $exception): ?OperationException
    {
        // Returned as-is rather than rebuilt, which is the only way its matched DN survives.
        if ($exception instanceof OperationException) {
            return $exception;
        }
        if ($exception instanceof UnrecoverableExceptionInterface) {
            return null;
        }
        if ($exception instanceof AnswerableExceptionInterface) {
            return new OperationException(
                $exception->getDiagnostic(),
                $exception->getCode(),
                $exception,
            );
        }

        return new OperationException(
            'The result could not be completed.',
            ResultCode::OTHER,
            $exception,
        );
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
