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

use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Socket\Tls\Certificate;

/**
 * Maps a verified TLS client certificate to an authorization identity for SASL EXTERNAL, resolved via the chain.
 */
interface ExternalCredentialMapperInterface
{
    /**
     * The authentication identity for the certificate (a dn:/u: authzId resolved via the identity resolver chain).
     *
     * Returning null rejects the certificate.
     */
    public function map(Certificate $certificate): ?AuthzId;
}
