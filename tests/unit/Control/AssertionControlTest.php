<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Control;

use FreeDSx\Ldap\Control\AssertionControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\TestCase;

final class AssertionControlTest extends TestCase
{
    public function test_it_has_the_assertion_oid(): void
    {
        self::assertSame(
            Control::OID_ASSERTION,
            (new AssertionControl(Filters::equal('cn', 'foo')))->getTypeOid(),
        );
    }

    public function test_it_is_critical_by_default(): void
    {
        self::assertTrue((new AssertionControl(Filters::equal('cn', 'foo')))->getCriticality());
    }

    public function test_it_can_be_non_critical(): void
    {
        self::assertFalse(
            (new AssertionControl(Filters::equal('cn', 'foo'), false))->getCriticality(),
        );
    }

    public function test_it_exposes_the_filter(): void
    {
        $filter = Filters::equal('cn', 'foo');

        self::assertSame(
            $filter,
            (new AssertionControl($filter))->getFilter(),
        );
    }
}
