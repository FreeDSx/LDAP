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

namespace spec\FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Protocol\RootDseLoader;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class RootDseLoaderSpec extends ObjectBehavior
{
    public function let(LdapClient $ldapClient): void
    {
        $this->beConstructedWith($ldapClient);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(RootDseLoader::class);
    }

    public function it_should_load_the_root_dse(LdapClient $ldapClient): void
    {
        $entry = Entry::fromArray('', []);

        $ldapClient
            ->read(
                '',
                Argument::any(),
            )
            ->willReturn($entry);

        $this->load()
            ->shouldBe($entry);
    }

    public function it_should_use_the_cached_root_dse_on_a_second_load_call(LdapClient $ldapClient): void
    {
        $entry = Entry::fromArray('', []);

        $ldapClient
            ->read(
                '',
                Argument::any(),
            )
            ->shouldBeCalledOnce()
            ->willReturn($entry);

        $this->load()
            ->shouldBe($entry);
    }

    public function it_should_not_use_the_cached_root_if_the_reload_param_is_used(LdapClient $ldapClient): void
    {
        $entry = Entry::fromArray('', []);

        $ldapClient
            ->read(
                '',
                Argument::any(),
            )
            ->shouldBeCalledTimes(2)
            ->willReturn($entry);

        $this->load();

        $this->load(reload: true)
            ->shouldBe($entry);
    }

    public function it_should_throw_an_exception_if_no_root_dse_is_returned(): void
    {
        $this->shouldThrow(OperationException::class)
            ->during('load');
    }
}
