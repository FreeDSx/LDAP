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

namespace FreeDSx\Ldap\Server\Backend\Auth;

use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use SensitiveParameter;

/**
 * Default password authenticator. Resolves the bind name to an Entry via a
 * BindNameResolverInterface, then verifies the supplied password against the
 * entry's userPassword attribute.
 *
 * Supported storage schemes: {SHA}, {SSHA}, {MD5}, {SMD5}, and plain-text.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PasswordAuthenticator implements PasswordAuthenticatableInterface
{
    public function __construct(
        private readonly BindNameResolverInterface $nameResolver,
        private readonly LdapBackendInterface $backend,
    ) {
    }

    public function verifyPassword(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): bool {
        $entry = $this->nameResolver->resolve(
            $name,
            $this->backend
        );

        if ($entry === null) {
            return false;
        }

        $attr = $entry->get('userPassword');

        if ($attr === null) {
            return false;
        }

        foreach ($attr->getValues() as $stored) {
            if ($this->checkPassword($password, $stored)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Verify a plain-text password against a (possibly hashed) stored value.
     *
     * Supports {SHA}, {SSHA}, {MD5}, {SMD5}, and plain-text storage.
     */
    private function checkPassword(
        #[SensitiveParameter]
        string $plain,
        string $stored,
    ): bool {
        if (str_starts_with($stored, '{SHA}')) {
            return base64_encode(sha1($plain, true)) === substr($stored, 5);
        }

        if (str_starts_with($stored, '{SSHA}')) {
            $decoded = base64_decode(substr($stored, 6));
            $salt = substr($decoded, 20);

            return substr($decoded, 0, 20) === sha1($plain . $salt, true);
        }

        if (str_starts_with($stored, '{MD5}')) {
            return base64_encode(md5($plain, true)) === substr($stored, 5);
        }

        if (str_starts_with($stored, '{SMD5}')) {
            $decoded = base64_decode(substr($stored, 6));
            $salt = substr($decoded, 16);

            return substr($decoded, 0, 16) === md5($plain . $salt, true);
        }

        return $plain === $stored;
    }
}
