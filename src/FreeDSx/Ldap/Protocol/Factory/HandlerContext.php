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

namespace FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Protocol\Queue\Budget\HeldResponses;
use FreeDSx\Ldap\Protocol\Queue\ConnectionControl;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Paging\PagingSessions;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;

/**
 * The per-connection roots a handler factory needs to finish constructing a handler.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class HandlerContext
{
    public function __construct(
        public ConnectionControl $connection,
        public EventLogger $eventLogger,
        public PagingSessions $pagingSessions,
        public HeldResponses $heldResponses,
        public ?PasswordPolicyContext $passwordPolicyContext = null,
    ) {}
}
