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

namespace FreeDSx\Ldap\Server\Backend\Write\SystemChange;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\Token\SystemToken;

/**
 * Applies server-generated writes, bypassing schema NO-USER-MODIFICATION and ACL checks.
 */
final readonly class SystemChangeWriter implements SystemChangeWriterInterface
{
    public function __construct(private WriteHandlerInterface $writeDispatcher) {}

    /**
     * @throws OperationException
     */
    public function write(
        Dn $dn,
        OperationalChanges $changes,
    ): void {
        if ($changes->isEmpty()) {
            return;
        }

        $this->writeDispatcher->handle(
            new UpdateCommand(
                $dn,
                $changes->changes,
            ),
            WriteContext::system(
                new SystemToken(),
                new ControlBag(),
            ),
        );
    }
}
