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

namespace Tests\Unit\FreeDSx\Ldap\Server\Initialization\Advisory;

use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Initialization\Advisory\HeldRequestSizeAdvisory;
use FreeDSx\Ldap\Server\Initialization\InitializationWarning;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class HeldRequestSizeAdvisoryTest extends TestCase
{
    /**
     * What the largest request allowed by default holds once decoded: 2,621,440 bytes carrying 100,000 elements.
     */
    private const LARGEST_HELD_BY_DEFAULT = 19_014_656;

    private NetworkConfig $network;

    protected function setUp(): void
    {
        $this->network = new NetworkConfig();
    }

    /**
     * @return array<string, array{int}>
     */
    public static function tooSmallProvider(): array
    {
        return [
            'smaller than its bytes' => [1_000_000],
            'smaller than its bytes and elements' => [10_000_000],
            'one byte short' => [self::LARGEST_HELD_BY_DEFAULT - 1],
        ];
    }

    #[DataProvider('tooSmallProvider')]
    public function test_it_warns_when_the_largest_request_allowed_holds_more_than_the_held_size(int $heldSize): void
    {
        self::assertEquals(
            [
                InitializationWarning::concurrencyLimited(
                    ConcurrencyLimitReason::HeldRequestSize,
                    [
                        'max_held_request_size' => $heldSize,
                        'max_request_size' => 2_621_440,
                    ],
                ),
            ],
            $this->advisoryFor($heldSize)->warnings(),
        );
    }

    public function test_it_does_not_warn_when_the_largest_request_allowed_fits_exactly(): void
    {
        self::assertSame(
            [],
            $this->advisoryFor(self::LARGEST_HELD_BY_DEFAULT)->warnings(),
        );
    }

    public function test_it_warns_when_requests_have_no_size_limit(): void
    {
        $this->network->setMaxRequestSize(0);

        self::assertCount(
            1,
            $this->advisoryFor(1_000_000_000)->warnings(),
        );
    }

    public function test_it_counts_one_element_for_every_two_bytes_when_elements_have_no_limit(): void
    {
        $this->network->setMaxRequestElements(0);

        self::assertSame(
            [1, 0],
            [
                count($this->advisoryFor(212_729_855)->warnings()),
                count($this->advisoryFor(212_729_856)->warnings()),
            ],
        );
    }

    public function test_it_does_not_warn_without_a_held_size_limit(): void
    {
        $this->network->setMaxRequestSize(0);

        self::assertSame(
            [],
            $this->advisoryFor(0)->warnings(),
        );
    }

    private function advisoryFor(int $heldSize): HeldRequestSizeAdvisory
    {
        return new HeldRequestSizeAdvisory(
            $this->network,
            $heldSize,
        );
    }
}
