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

namespace FreeDSx\Ldap\Ldif\Url;

use FreeDSx\Ldap\Exception\LdifUrlException;

/**
 * Resolves the URL form of an LDIF value (RFC 2849 "name:< url") to the bytes it names.
 *
 * @api
 */
interface LdifUrlResolverInterface
{
    /**
     * @throws LdifUrlException when the scheme is not handled or the content cannot be read
     */
    public function resolve(string $url): string;
}
