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
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use Throwable;

use function microtime;

/**
 * Times each message and records its operation outcome to the metrics recorder.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class MetricsMiddleware implements MiddlewareInterface
{
    /**
     * @param OperationRollupCoordinator|null $rollup Streams each op to the parent so cn=monitor stays fresh on
     *                                                long-lived connections (null under Swoole and when monitor is off).
     */
    public function __construct(
        private MetricsRecorderInterface $recorder,
        private ?OperationRollupCoordinator $rollup = null,
    ) {}

    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        $request = $context->message->getRequest();
        $operation = OperationType::classify($request);
        $this->recorder->operationStarted($operation);
        $startedAt = microtime(true);

        try {
            $stream = $next->handle($context);
        } catch (OperationException $e) {
            // Only front-of-chain failures (bind/authorization) reach here; operation failures resolve as outcomes.
            $this->record(
                $request,
                $operation,
                false,
                microtime(true) - $startedAt,
                $e->getCode(),
            );

            throw $e;
        } catch (Throwable $e) {
            // An unexpected failure still has to clear the in-flight gauge and be counted as a failed op.
            $this->record(
                $request,
                $operation,
                false,
                microtime(true) - $startedAt,
                ResultCode::OPERATIONS_ERROR,
            );

            throw $e;
        }

        $result = $stream->outcome();
        $this->record(
            $request,
            $operation,
            $result->outcome() === OperationOutcome::Succeeded,
            microtime(true) - $startedAt,
            $result->resultCode(),
        );

        return $stream;
    }

    private function record(
        RequestInterface $request,
        OperationType $operation,
        bool $succeeded,
        float $durationSeconds,
        int $resultCode,
    ): void {
        $this->recorder->operationObserved(new OperationObservation(
            $operation,
            $succeeded,
            $durationSeconds,
            $operation->hasResponse()
                ? $resultCode
                : null,
            $this->bindMethod($request),
            $this->searchScope($request),
        ));
        $this->rollup?->flush();
    }

    private function bindMethod(RequestInterface $request): ?string
    {
        return match (true) {
            $request instanceof AnonBindRequest => 'anonymous',
            $request instanceof SaslBindRequest => 'sasl',
            $request instanceof SimpleBindRequest => 'simple',
            default => null,
        };
    }

    private function searchScope(RequestInterface $request): ?string
    {
        if (!$request instanceof SearchRequest) {
            return null;
        }

        return match ($request->getScope()) {
            SearchRequest::SCOPE_BASE_OBJECT => 'base',
            SearchRequest::SCOPE_SINGLE_LEVEL => 'one',
            SearchRequest::SCOPE_WHOLE_SUBTREE => 'sub',
            default => null,
        };
    }
}
