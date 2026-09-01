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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;

/**
 * Records whether the client asked for password policy information, so the response control never goes to a client
 * that did not request it.
 *
 * Ahead of everything that can answer, since a bind and a password-change refusal both respond outside this pipeline.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PasswordPolicyRequestMiddleware implements MiddlewareInterface
{
    public function __construct(private PasswordPolicyContext $policyContext) {}

    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        // a refusal raised below answers after this middleware has unwound.
        $this->policyContext->clear();
        $this->policyContext->setResponseRequested(
            $context->message->controls()->has(Control::OID_PWD_POLICY),
        );

        return $next->handle($context);
    }
}
