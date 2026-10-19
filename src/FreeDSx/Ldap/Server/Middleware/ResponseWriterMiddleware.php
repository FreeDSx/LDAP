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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\MatchedDnAccessFilterTrait;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\OperationTargetDn;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\FailedOperationResult;
use FreeDSx\Ldap\Server\Operation\FailureAnswerTrait;
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
    use FailureAnswerTrait;
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
                    self::asProvided(
                        $exception->getMatchedDn(),
                        $context->message->getRequest(),
                    ),
                    $context->tokenOrFail(),
                    $this->backend,
                    $this->accessControl,
                ),
                [],
                ...$exception->controls()->toArray(),
            )],
            new FailedOperationResult(
                $context->message,
                $exception,
            ),
        );
    }

    /**
     * RFC 4511 4.1.9: the matchedDN is a truncated form of the provided name, in the spelling the request used.
     */
    private static function asProvided(
        ?Dn $matchedDn,
        RequestInterface $request,
    ): ?Dn {
        if ($matchedDn === null) {
            return null;
        }
        $matched = $matchedDn->normalizedString();

        foreach (OperationTargetDn::named($request) as $provided) {
            $truncated = self::truncatedTo(
                $provided,
                $matched,
            );

            if ($truncated !== null) {
                return $truncated;
            }
        }

        return $matchedDn;
    }

    /**
     * The provided DN, or the ancestor of it, that names the same entry as the matched one.
     */
    private static function truncatedTo(
        Dn $provided,
        string $matched,
    ): ?Dn {
        for ($candidate = $provided; $candidate !== null; $candidate = $candidate->getParent()) {
            if ($candidate->normalizedString() === $matched) {
                return $candidate;
            }
        }

        return null;
    }
}
