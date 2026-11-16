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

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\Exception\BindException;

/**
 * Switches the password policy harness to its subentry policy run and locks accounts governed by it.
 */
trait PasswordPolicyServerTrait
{
    /**
     * The pwdMaxFailure the subentry seed configures.
     */
    private const MAX_FAILURE = 2;

    /**
     * Restarts the server with no policy configured in PHP, leaving the DIT as the only source of enforcement.
     *
     * @param list<string> $options
     */
    private function useSubentryPolicyServer(array $options = []): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                '--subentry-policy',
                ...$options,
            ],
        );
    }

    private function failBinds(
        string $dn,
        int $times,
    ): void {
        for ($i = 0; $i < $times; $i++) {
            try {
                $this->ldapClient()->bind(
                    $dn,
                    'not-the-password',
                );

                self::fail('A bind with the wrong password should not succeed.');
            } catch (BindException) {
                // Expected: the point is to accumulate failures.
            }
        }
    }
}
