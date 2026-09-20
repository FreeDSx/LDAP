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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolations;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteControlEvaluator;
use FreeDSx\Ldap\Server\Backend\Write\Routing\WriteRequestRouter;
use FreeDSx\Ldap\Server\Operation\CompareOperationResult;
use FreeDSx\Ldap\Server\Operation\WriteOperationResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles generic requests that are dispatched to the backend.
 *
     * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerDispatchHandler implements ServerProtocolHandlerInterface
{
    private ReadEntryControlHandler $readEntryControlHandler;

    public function __construct(
        private ReadBackendInterface $backend,
        private WriteRequestRouter $router,
        private AccessControlInterface $accessControl,
        private AssertionEvaluator $assertions,
        Schema $schema,
        private ResponseFactory $responseFactory = new ResponseFactory(),
    ) {
        $this->readEntryControlHandler = new ReadEntryControlHandler(
            $schema,
            $this->accessControl,
        );
    }

    /**
     * {@inheritDoc}
     *
     * @throws EncoderException
     * @throws OperationException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        $request = $message->getRequest();

        if ($request instanceof Request\CompareRequest) {
            return $this->handleCompare(
                $message,
                $request,
                $token,
            );
        }

        return $this->handleWrite(
            $message,
            $token,
        );
    }

    /**
     * @throws OperationException
     * @throws EncoderException
     */
    private function handleCompare(
        LdapMessageRequest $message,
        Request\CompareRequest $request,
        TokenInterface $token,
    ): ResponseStream {
        // The assertion and the comparison are answered from one read of the entry (RFC 4528 §3).
        $entry = $this->backend->getOrFail($request->getDn());
        $this->assertions->assertSatisfiedBy(
            $entry,
            $message->controls(),
            $token,
        );
        $match = $this->backend->compare(
            $entry,
            $request->getFilter(),
        );

        return ResponseStream::of(
            [$this->responseFactory->getStandardResponse(
                $message,
                $match
                    ? ResultCode::COMPARE_TRUE
                    : ResultCode::COMPARE_FALSE,
            )],
            CompareOperationResult::completed(
                $message,
                $match,
            ),
        );
    }

    /**
     * @throws OperationException
     * @throws EncoderException
     */
    private function handleWrite(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        $controls = $message->controls();
        $schemaViolations = new SchemaViolations();
        $controlEvaluator = new WriteControlEvaluator(
            $this->assertions,
            $token,
            $controls,
        );

        $this->router->route(
            $message->getRequest(),
            new WriteContext(
                $token,
                $controls,
                schemaViolations: $schemaViolations,
                controlEvaluator: $controlEvaluator,
            ),
        );

        $preRead = $this->readEntryControlHandler->preRead(
            $controlEvaluator->preReadEntry(),
            $controls,
            $token,
        );
        $postRead = $this->readEntryControlHandler->postRead(
            $controlEvaluator->postReadEntry(),
            $controls,
            $token,
        );

        return ResponseStream::of(
            [$this->responseFactory->getStandardResponse(
                $message,
                ResultCode::SUCCESS,
                '',
                null,
                [],
                ...$this->successControls($preRead, $postRead),
            )],
            WriteOperationResult::success(
                $message,
                $schemaViolations,
            ),
        );
    }

    /**
     * @return Control[]
     */
    private function successControls(
        ?Control $preRead,
        ?Control $postRead,
    ): array {
        return array_values(array_filter([
            $preRead,
            $postRead,
        ]));
    }
}
