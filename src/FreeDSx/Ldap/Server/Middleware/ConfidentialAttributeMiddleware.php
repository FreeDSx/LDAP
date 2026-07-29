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

use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\AccessControl\ConfidentialFilterRewriter;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\CompareOperationResult;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;

/**
 * Withholds confidential attributes from assertions before the request reaches storage.
 *
 * An assertion the requester cannot satisfy is answered here, so the value never selects candidates and a
 * guess costs the same whether or not it was right.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ConfidentialAttributeMiddleware implements MiddlewareInterface
{
    public function __construct(
        private ConfidentialFilterRewriter $rewriter,
        private ResponseFactory $responseFactory = new ResponseFactory(),
    ) {}

    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        $request = $context->message->getRequest();

        if ($request instanceof SearchRequest) {
            return $this->processSearch($context, $next, $request);
        }

        if ($request instanceof CompareRequest) {
            return $this->processCompare($context, $next, $request);
        }

        return $next->handle($context);
    }

    private function processSearch(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
        SearchRequest $request,
    ): ResponseStream {
        $rewritten = $this->rewriter->rewrite(
            $request->getFilter(),
            $context->tokenOrFail(),
        );

        if ($this->rewriter->isAbsoluteFalse($rewritten)) {
            return ResponseStream::of(
                [$this->responseFactory->getStandardResponse($context->message)],
                OperationOutcomeResult::succeeded(),
            );
        }

        $request->setFilter($rewritten);

        return $next->handle($context);
    }

    /**
     * Compare is the same disclosure by another name, and RFC 4511 folds Undefined into compareFalse.
     */
    private function processCompare(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
        CompareRequest $request,
    ): ResponseStream {
        $rewritten = $this->rewriter->rewrite(
            $request->getFilter(),
            $context->tokenOrFail(),
        );

        if (!$this->rewriter->isAbsoluteFalse($rewritten)) {
            return $next->handle($context);
        }

        $result = CompareOperationResult::completed(
            $context->message,
            false,
        );

        return ResponseStream::of(
            [$this->responseFactory->getStandardResponse(
                $context->message,
                $result->resultCode(),
            )],
            $result,
        );
    }
}
