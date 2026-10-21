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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler\Admission;

use FreeDSx\Ldap\Protocol\ServerProtocolHandler\Admission\AttributeAdmission;
use FreeDSx\Ldap\Server\AccessControl\Read\ReadVerdict;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AttributeAdmissionTest extends TestCase
{
    #[DataProvider('admissionProvider')]
    public function test_it_settles_whether_every_entry_returns_the_attribute(
        bool $returned,
        ReadVerdict $read,
        bool $concernsFilter,
        ?bool $expected,
    ): void {
        $subject = new AttributeAdmission(
            'cn',
            $returned,
            $read,
            $concernsFilter,
        );

        self::assertSame(
            $expected,
            $subject->returnedOnEveryEntry(),
        );
    }

    public static function admissionProvider(): Generator
    {
        yield 'allowed and selected' => [
            true,
            ReadVerdict::Allow,
            false,
            true,
        ];
        yield 'allowed and selected while the filter reads it' => [
            true,
            ReadVerdict::Allow,
            true,
            true,
        ];
        yield 'allowed but not selected' => [
            false,
            ReadVerdict::Allow,
            true,
            false,
        ];
        yield 'denied where the filter does not read it' => [
            true,
            ReadVerdict::Deny,
            false,
            false,
        ];
        yield 'denied where the filter reads it' => [
            true,
            ReadVerdict::Deny,
            true,
            null,
        ];
        yield 'decided on each entry' => [
            true,
            ReadVerdict::PerEntry,
            false,
            null,
        ];
    }
}
