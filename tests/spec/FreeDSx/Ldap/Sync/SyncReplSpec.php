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

namespace spec\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\SyncHandlerInterface;
use FreeDSx\Ldap\Sync\SyncRepl;
use PhpSpec\ObjectBehavior;

class SyncReplSpec extends ObjectBehavior
{
    public function let(LdapClient $client,): void
    {
        $this->beConstructedWith($client,);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(SyncRepl::class);
    }
}
