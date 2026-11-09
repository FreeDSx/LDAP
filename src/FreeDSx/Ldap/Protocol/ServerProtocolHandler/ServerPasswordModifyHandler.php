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

use FreeDSx\Ldap\Exception\AdminLimitExceededException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Request\PasswordModifyRequestDecoder;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Operation\PasswordModifyOperationResult;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyResult;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyService;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

use function is_string;

/**
 * Adapts RFC 3062 Password Modify requests to {@see PasswordModifyService}: decode, delegate, build the response.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerPasswordModifyHandler implements ServerProtocolHandlerInterface
{
    /**
     * @param int|null $elementBudget the elements a request value may hold, or null for no limit.
     */
    public function __construct(
        private PasswordModifyService $service,
        private PasswordModifyRequestDecoder $requestDecoder,
        private ?int $elementBudget = null,
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

        $request = $this->decodeRequest($message);
        $this->assertNamesAField($request);

        return $this->service->change(
            $request,
            $token,
            $message->controls(),
        );
    }

    /**
     * Decodes the request value, answering one that is malformed or carries an unrecognized field as a protocol error.
     *
     * @throws OperationException
     */
    private function decodeRequest(LdapMessageRequest $message): PasswordModifyRequest
    {
        $request = $message->getRequest();
        if ($request instanceof PasswordModifyRequest) {
            return $request;
        }

        try {
            return $this->requestDecoder->decode(
                $this->valueOf($request),
                new DecodeContext($this->elementBudget),
            );
        } catch (ProtocolException $e) {
            throw new OperationException(
                $e->getMessage(),
                ResultCode::PROTOCOL_ERROR,
                $e,
            );
        } catch (AdminLimitExceededException $e) {
            throw new OperationException(
                $e->getDiagnostic(),
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e,
            );
        }
    }

    /**
     * The value as the client sent it, which a request decoded from the wire always carries as a string.
     *
     * @throws ProtocolException
     */
    private function valueOf(RequestInterface $request): ?string
    {
        $value = $request instanceof ExtendedRequest
            ? $request->getValue()
            : null;
        if ($value !== null && !is_string($value)) {
            throw new ProtocolException('The password modify request is malformed.');
        }

        return $value;
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
