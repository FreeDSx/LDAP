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

namespace Tests\Unit\FreeDSx\Ldap\Server\Utility;

use FreeDSx\Ldap\Server\Utility\Uuid;
use PHPUnit\Framework\TestCase;

final class UuidTest extends TestCase
{
    public function test_it_should_return_a_valid_uuid_v4_string(): void
    {
        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            Uuid::v4(),
        );
    }

    public function test_it_should_return_a_unique_value_on_each_call(): void
    {
        self::assertNotSame(
            Uuid::v4(),
            Uuid::v4(),
        );
    }

    public function test_it_should_decode_the_binary_form_to_the_dashed_form(): void
    {
        self::assertSame(
            '0f8fad5b-d9cb-469f-a165-70867728950e',
            Uuid::fromBinary(pack('H*', '0f8fad5bd9cb469fa16570867728950e')),
        );
    }

    public function test_it_should_round_trip_a_generated_uuid_through_both_forms(): void
    {
        $uuid = Uuid::v4();

        self::assertSame(
            $uuid,
            Uuid::fromBinary(Uuid::toBinary($uuid)),
        );
    }
}
