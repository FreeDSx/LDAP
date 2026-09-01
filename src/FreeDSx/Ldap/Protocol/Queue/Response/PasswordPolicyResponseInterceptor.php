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

namespace FreeDSx\Ldap\Protocol\Queue\Response;

use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;

/**
 * Attaches the password-policy response control to the next outgoing response when the context holds one.
 *
 * Consumes the outcome either way. A response is sent for every request whatever route answered it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PasswordPolicyResponseInterceptor implements ResponseInterceptor
{
    public function __construct(private PasswordPolicyContext $context) {}

    public function intercept(LdapMessageResponse $response): LdapMessageResponse
    {
        $control = $this->context->buildResponseControl();
        $this->context->clear();

        if ($control === null) {
            return $response;
        }

        $response->controls()->add($control);

        return $response;
    }
}
