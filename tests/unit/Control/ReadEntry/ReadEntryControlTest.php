<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Control\ReadEntry;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ReadEntry\PostReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadControl;
use PHPUnit\Framework\TestCase;

final class ReadEntryControlTest extends TestCase
{
    public function test_pre_read_has_the_pre_read_oid(): void
    {
        self::assertSame(
            Control::OID_PRE_READ,
            (new PreReadControl('cn'))->getTypeOid(),
        );
    }

    public function test_post_read_has_the_post_read_oid(): void
    {
        self::assertSame(
            Control::OID_POST_READ,
            (new PostReadControl('cn'))->getTypeOid(),
        );
    }

    public function test_it_is_not_critical_by_default(): void
    {
        self::assertFalse((new PreReadControl('cn'))->getCriticality());
    }

    public function test_it_exposes_the_requested_attributes(): void
    {
        self::assertSame(
            ['cn', 'sn'],
            (new PreReadControl('cn', 'sn'))->getAttributes(),
        );
    }
}
