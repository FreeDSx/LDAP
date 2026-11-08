<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Control\ReadEntry;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ReadEntry\PostReadResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadResponseControl;
use FreeDSx\Ldap\Entry\Entry;
use PHPUnit\Framework\TestCase;

final class ReadEntryResponseControlTest extends TestCase
{
    public function test_pre_read_response_has_the_pre_read_oid(): void
    {
        self::assertSame(
            Control::OID_PRE_READ,
            (new PreReadResponseControl(Entry::fromArray('cn=foo,dc=ex,dc=com')))->getTypeOid(),
        );
    }

    public function test_post_read_response_has_the_post_read_oid(): void
    {
        self::assertSame(
            Control::OID_POST_READ,
            (new PostReadResponseControl(Entry::fromArray('cn=foo,dc=ex,dc=com')))->getTypeOid(),
        );
    }

    public function test_it_exposes_the_entry(): void
    {
        $entry = Entry::fromArray('cn=foo,dc=ex,dc=com', ['cn' => ['foo']]);

        self::assertSame(
            $entry,
            (new PreReadResponseControl($entry))->getEntry(),
        );
    }
}
