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

use Closure;
use DateTimeImmutable;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Schema\SchemaLoadMode;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Config\SchemaConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

final class SchemaConfigTest extends TestCase
{
    private FrozenClock $clock;

    private SchemaConfig $subject;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString('2026-10-12T10:00:00Z');
        $this->subject = new SchemaConfig($this->clock);
    }

    public function test_the_schema_takes_its_shape_when_the_config_is_created(): void
    {
        self::assertEquals(
            new DateTimeImmutable('2026-10-12T10:00:00Z'),
            $this->subject->getChangedAt(),
        );
    }

    /**
     * @param Closure(SchemaConfig): mixed $change
     */
    #[DataProvider('shapeChangeProvider')]
    public function test_a_change_to_the_schemas_shape_moves_its_time(Closure $change): void
    {
        $this->clock->setTo(new DateTimeImmutable('2026-10-12T11:00:00Z'));

        $change($this->subject);

        self::assertEquals(
            new DateTimeImmutable('2026-10-12T11:00:00Z'),
            $this->subject->getChangedAt(),
        );
    }

    /**
     * @return iterable<string, array{Closure(SchemaConfig): mixed}>
     */
    public static function shapeChangeProvider(): iterable
    {
        yield 'replacing the sources' => [
            static fn(SchemaConfig $config): SchemaConfig => $config->setSources(SchemaResource::Core),
        ];
        yield 'adding a source' => [
            static fn(SchemaConfig $config): SchemaConfig => $config->addSource(SchemaResource::Core),
        ];
        yield 'changing the load mode' => [
            static fn(SchemaConfig $config): SchemaConfig => $config->setLoadMode(SchemaLoadMode::Lenient),
        ];
    }

    /**
     * @param Closure(SchemaConfig): mixed $change
     */
    #[DataProvider('settingProvider')]
    public function test_a_setting_that_leaves_the_schema_alone_keeps_its_time(Closure $change): void
    {
        $this->clock->setTo(new DateTimeImmutable('2026-10-12T11:00:00Z'));

        $change($this->subject);

        self::assertEquals(
            new DateTimeImmutable('2026-10-12T10:00:00Z'),
            $this->subject->getChangedAt(),
        );
    }

    /**
     * @return iterable<string, array{Closure(SchemaConfig): mixed}>
     */
    public static function settingProvider(): iterable
    {
        yield 'the validation mode' => [
            static fn(SchemaConfig $config): SchemaConfig => $config->setValidationMode(SchemaValidationMode::Lenient),
        ];
        yield 'the attribute value limit' => [
            static fn(SchemaConfig $config): SchemaConfig => $config->setMaxAttributeValues(25),
        ];
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
