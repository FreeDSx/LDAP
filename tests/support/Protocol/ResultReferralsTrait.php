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

namespace Tests\Support\FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Protocol\LdapEncoder;

trait ResultReferralsTrait
{
    private static function referralsField(string ...$urls): IncompleteType
    {
        $encoder = new LdapEncoder();
        $content = '';
        foreach ($urls as $url) {
            $content .= $encoder->encode(Asn1::octetString($url));
        }

        return Asn1::context(
            3,
            (new IncompleteType($content))->setIsConstructed(true),
        );
    }
}
