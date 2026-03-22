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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Sasl\Mechanism\ScramMechanism;

/**
 * Extracts the username from a SCRAM client-first-message.
 *
 * SCRAM is client-initiated: the username is sent in the first message as 'n=<username>'
 * within the client-first-message-bare (after the GS2 header). RFC 5802 encodes ',' as
 * '=2C' and '=' as '=3D' within the username field.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ScramUsernameExtractor implements SaslUsernameExtractorInterface
{
    /**
     * {@inheritDoc}
     */
    public function extractUsername(string $mechanism, string $credentials): string
    {
        // Strip the GS2 header (everything up to and including ',,').
        $pos = strpos($credentials, ',,');
        $bare = $pos !== false
            ? substr($credentials, $pos + 2)
            : $credentials;

        // Extract the 'n=' field.
        if (preg_match('/(?:^|,)n=([^,]*)/', $bare, $m)) {
            // Unescape RFC 5802 username encoding.
            return str_replace(
                ['=2C', '=3D'],
                [',', '='],
                $m[1]
            );
        }

        throw new OperationException(
            sprintf('The %s credentials did not contain a username.', $mechanism),
            ResultCode::PROTOCOL_ERROR
        );
    }

    /**
     * {@inheritDoc}
     */
    public function supports(string $mechanism): bool
    {
        return in_array(
            $mechanism,
            ScramMechanism::VARIANTS,
            true,
        );
    }
}
