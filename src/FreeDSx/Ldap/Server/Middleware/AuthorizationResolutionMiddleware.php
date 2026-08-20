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

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\DispatchAuthorizer;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;

/**
 * Resolves the effective identity for an operation, rejecting requests that need authentication or a password change.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AuthorizationResolutionMiddleware implements MiddlewareInterface
{
    private const PASSWORD_CHANGE_REQUIRED = 'The password must be changed before any other operation is permitted.';

    public function __construct(
        private DispatchAuthorizer $dispatchAuthorizer,
        private ?PasswordPolicyContext $passwordPolicyContext = null,
    ) {}

    /**
     * @throws OperationException
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        $authorization = $this->dispatchAuthorizer->authorize($context->message);

        if ($authorization->requiresAuthentication()) {
            throw new OperationException(
                'Authentication required.',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            );
        }

        if ($authorization->requiresPasswordChange()) {
            throw $this->passwordChangeRequired();
        }

        return $next->handle($context->withToken($authorization->token()));
    }

    /**
     * The response control rides out via {@see \FreeDSx\Ldap\Protocol\Queue\Response\PasswordPolicyResponseInterceptor}.
     *
     * draft-behera-11 §8.3 pairs changeAfterReset with insufficientAccessRights.
     */
    private function passwordChangeRequired(): OperationException
    {
        $this->passwordPolicyContext?->setOutcome(PasswordPolicyOutcome::deny(
            PwdPolicyError::CHANGE_AFTER_RESET,
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            self::PASSWORD_CHANGE_REQUIRED,
        ));

        return new OperationException(
            self::PASSWORD_CHANGE_REQUIRED,
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
        );
    }
}
