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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Decoder;

use Closure;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\DecodeBaseline;
use Tests\Support\FreeDSx\Ldap\Protocol\DecodeOutcome;

final class DecodeBaselineTest extends TestCase
{
    /**
     * @var Closure(string): LdapMessageRequest
     */
    private Closure $decodeRequest;

    /**
     * @var Closure(string): LdapMessageResponse
     */
    private Closure $decodeResponse;

    protected function setUp(): void
    {
        $this->decodeRequest = static fn(string $pdu): LdapMessageRequest => LdapMessageRequest::fromAsn1(
            (new LdapEncoder())->decode($pdu),
        );
        $this->decodeResponse = static fn(string $pdu): LdapMessageResponse => LdapMessageResponse::fromAsn1(
            (new LdapEncoder())->decode($pdu),
        );
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function requests(): array
    {
        return DecodeBaseline::requests();
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function responses(): array
    {
        return DecodeBaseline::responses();
    }

    #[DataProvider('requests')]
    public function testTheServerDecodesEachRequestAsRecorded(
        string $pdu,
        string $outcome,
    ): void {
        self::assertSame(
            $outcome,
            DecodeOutcome::of(
                $this->decodeRequest,
                $pdu,
            ),
        );
    }

    #[DataProvider('responses')]
    public function testTheClientDecodesEachResponseAsRecorded(
        string $pdu,
        string $outcome,
    ): void {
        self::assertSame(
            $outcome,
            DecodeOutcome::of(
                $this->decodeResponse,
                $pdu,
            ),
        );
    }
}
