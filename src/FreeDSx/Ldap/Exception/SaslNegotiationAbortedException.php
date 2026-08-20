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

namespace FreeDSx\Ldap\Exception;

use Exception;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;

/**
 * A bind arriving mid-exchange that RFC 4511 4.2.1 defines as abandoning the negotiation in progress.
 *
 * Carries that bind so it can be authenticated in place of the one it replaced.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SaslNegotiationAbortedException extends Exception
{
    public function __construct(public readonly LdapMessageRequest $request)
    {
        parent::__construct('The SASL negotiation was aborted by the client.');
    }
}
