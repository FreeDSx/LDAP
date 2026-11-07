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

namespace FreeDSx\Ldap\Protocol\Decoder;

use FreeDSx\Ldap\Protocol\LdapEncoder;

/**
 * Makes the context each received message decodes its nested parts through.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DecodeContextFactory
{
    public function create(): DecodeContext
    {
        return new DecodeContext(new LdapEncoder());
    }
}
