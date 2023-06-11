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

namespace spec\FreeDSx\Ldap\Search;

use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\SyncHandlerInterface;
use FreeDSx\Ldap\Search\SyncRepl;
use PhpSpec\ObjectBehavior;

class SyncReplSpec extends ObjectBehavior
{
    public function let(
        LdapClient $client,
        SyncHandlerInterface $syncHandler,
    ): void {
        $this->beConstructedWith(
            $client,
            Operations::sync($syncHandler->getWrappedObject())
        );
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(SyncRepl::class);
    }
}
