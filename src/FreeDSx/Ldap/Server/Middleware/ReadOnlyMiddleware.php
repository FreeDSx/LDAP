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
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Response\AddResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\ModifyDnResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Config\Replication\ConsumerConfig;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;

use function in_array;

/**
 * Rejects or refers client write operations on a read-only replica.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReadOnlyMiddleware implements MiddlewareInterface
{
    private const DIAGNOSTIC = 'This server is a read-only replica.';

    /**
     * @var list<OperationType>
     */
    private const WRITE_OPERATIONS = [
        OperationType::Add,
        OperationType::Modify,
        OperationType::Delete,
        OperationType::ModifyDn,
        OperationType::PasswordModify,
    ];

    public function __construct(private ConsumerConfig $consumerConfig) {}

    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        $request = $context->message->getRequest();

        $isWrite = in_array(
            OperationType::classify($request),
            self::WRITE_OPERATIONS,
            true,
        );

        if (!$isWrite) {
            return $next->handle($context);
        }

        if (!$this->consumerConfig->shouldReferWrites()) {
            throw new OperationException(
                self::DIAGNOSTIC,
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }

        return ResponseStream::of(
            [$this->referralResponse(
                $request,
                $context->message->getMessageId(),
            )],
            OperationOutcomeResult::failed(ResultCode::REFERRAL),
        );
    }

    private function referralResponse(
        RequestInterface $request,
        int $messageId,
    ): LdapMessageResponse {
        $referrals = $this->consumerConfig->referralUrls();

        // The default covers PasswordModify (an extended operation); the write gate guarantees no other type reaches here.
        $response = match (true) {
            $request instanceof AddRequest => new AddResponse(
                ResultCode::REFERRAL,
                '',
                self::DIAGNOSTIC,
                ...$referrals,
            ),
            $request instanceof ModifyRequest => new ModifyResponse(
                ResultCode::REFERRAL,
                '',
                self::DIAGNOSTIC,
                ...$referrals,
            ),
            $request instanceof DeleteRequest => new DeleteResponse(
                ResultCode::REFERRAL,
                '',
                self::DIAGNOSTIC,
                ...$referrals,
            ),
            $request instanceof ModifyDnRequest => new ModifyDnResponse(
                ResultCode::REFERRAL,
                '',
                self::DIAGNOSTIC,
                ...$referrals,
            ),
            default => new ExtendedResponse(
                new LdapResult(
                    ResultCode::REFERRAL,
                    '',
                    self::DIAGNOSTIC,
                    ...$referrals,
                ),
            ),
        };

        return new LdapMessageResponse(
            $messageId,
            $response,
        );
    }
}
