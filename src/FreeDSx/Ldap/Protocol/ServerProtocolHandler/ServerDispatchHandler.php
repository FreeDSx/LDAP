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
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolations;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteControlEvaluator;
use FreeDSx\Ldap\Server\Backend\Write\Routing\WriteRequestRouter;
use FreeDSx\Ldap\Server\Operation\WriteOperationResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles the write requests that are dispatched to the backend.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerDispatchHandler implements ServerProtocolHandlerInterface
{
    public function __construct(
        private WriteRequestRouter $router,
        private AssertionEvaluator $assertions,
        private ReadEntryControlHandler $readEntryControlHandler,
        private ResponseFactory $responseFactory = new ResponseFactory(),
    ) {}

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
