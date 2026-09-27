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

namespace Tests\Unit\FreeDSx\Ldap\Server\Config;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Config\SchemaConfig;
use PHPUnit\Framework\TestCase;

final class SchemaConfigTest extends TestCase
{
    private SchemaConfig $subject;

    protected function setUp(): void
    {
        $this->subject = new SchemaConfig();
    }

    public function test_it_defaults_the_attribute_value_limit_to_the_validators_default(): void
    {
        self::assertSame(
            SchemaValidator::DEFAULT_MAX_VALUES,
            $this->subject->getMaxAttributeValues(),
        );
    }

    public function test_the_attribute_value_limit_can_be_lowered(): void
    {
        $this->subject->setMaxAttributeValues(25);

        self::assertSame(
            25,
            $this->subject->getMaxAttributeValues(),
        );
    }

    public function test_the_attribute_value_limit_can_be_lifted_with_zero(): void
    {
        $this->subject->setMaxAttributeValues(0);

        self::assertSame(
            0,
            $this->subject->getMaxAttributeValues(),
        );
    }

    public function test_a_negative_attribute_value_limit_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The attribute value limit cannot be negative.');

        $this->subject->setMaxAttributeValues(-1);
    }
}
