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

namespace FreeDSx\Ldap\Server\RequestHandler;

/**
 * Implement this interface alongside RequestHandlerInterface to support server-side SASL authentication
 * with challenge-based mechanisms (DIGEST-MD5, CRAM-MD5) that require plaintext password lookup.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface SaslHandlerInterface
{
    /**
     * Return the plaintext password for a given username and SASL mechanism. This is needed so the server
     * can compute and verify the expected digest / response from the client.
     *
     * Return null if the user does not exist or should not be allowed to authenticate.
     */
    public function getPassword(
        string $username,
        string $mechanism,
    ): ?string;
}
