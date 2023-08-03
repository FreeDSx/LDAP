<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace spec\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\Protocol\LdapMessageResponse;

/**
 * Only used to test message handler processing during cancellations.
 *
 * @internal
 */
class MockCancelResponseProcessor
{
    public function __invoke(LdapMessageResponse $messageResponse,): void
    {
    }
}
