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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Operation\PasswordModifyOperationResult;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyResult;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyService;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Adapts RFC 3062 Password Modify requests to {@see PasswordModifyService}: decode, delegate, build the response.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerPasswordModifyHandler implements ServerProtocolHandlerInterface
{
    public function __construct(
        private PasswordModifyService $service,
        private ResponseFactory $responseFactory = new ResponseFactory(),
    ) {}

    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        try {
            $result = $this->changePassword(
                $message,
                $token,
            );
        } catch (OperationException $e) {
            return ResponseStream::of(
                [$this->responseFactory->getStandardResponse(
                    $message,
                    $e->getCode(),
                    $e->getMessage(),
                )],
                PasswordModifyOperationResult::failure(
                    $message,
                    $e,
                    null,
                ),
            );
        }

        return ResponseStream::reply(
            $message,
            PasswordModifyOperationResult::success(
                $message,
                $result->targetDn,
            ),
            new PasswordModifyResponse(
                new LdapResult(ResultCode::SUCCESS),
                $result->generatedPassword,
            ),
        );
    }

    /**
     * @throws OperationException
     */
    private function changePassword(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): PasswordModifyResult {
        if (!$token instanceof AuthenticatedTokenInterface) {
            throw new OperationException(
                'Authentication required.',
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }

        /** @var ExtendedRequest $raw */
        $raw = $message->getRequest();
        $request = PasswordModifyRequest::fromAsn1($raw->toAsn1());
        $this->assertNamesAField($request);

        return $this->service->change(
            $request,
            $token,
            $message->controls(),
        );
    }

    /**
     * RFC 3062 2.1: a request value carries one or more fields.
     *
     * @throws OperationException
     */
    private function assertNamesAField(PasswordModifyRequest $request): void
    {
        $namesNothing = $request->getUsername() === null
            && $request->getOldPassword() === null
            && $request->getNewPassword() === null;

        if ($namesNothing) {
            throw new OperationException(
                'The password modify request names no field.',
                ResultCode::PROTOCOL_ERROR,
            );
        }
    }
}
