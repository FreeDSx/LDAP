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
 * The default, so LDIF cannot name content to read until a resolver is configured deliberately.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RefusingUrlResolver implements LdifUrlResolverInterface
{
    public function resolve(string $url): string
    {
        throw new LdifUrlException('URL-referenced values ("name:< url") need a resolver, which none is configured');
    }
}
