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

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Protocol\Decoder\RequestMessageDecoder;
use FreeDSx\Ldap\Protocol\Decoder\ResponseMessageDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\DecodeBaseline;
use Tests\Support\FreeDSx\Ldap\Protocol\DecodeOutcome;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class DecodeBaselineTest extends TestCase
{
    use ServerContainerTrait;

    private RequestMessageDecoder $requestDecoder;

    private ResponseMessageDecoder $responseDecoder;

    protected function setUp(): void
    {
        $this->requestDecoder = $this->fromContainer(RequestMessageDecoder::class);
        $this->responseDecoder = Container::forClient(new ClientOptions())->get(ResponseMessageDecoder::class);
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
                fn(string $pdu): LdapMessageRequest => $this->requestDecoder->decode((new LdapEncoder())->decode($pdu)),
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
                fn(string $pdu): LdapMessageResponse => $this->responseDecoder->decode(
                    (new LdapEncoder())->decode($pdu),
                ),
                $pdu,
            ),
        );
    }
}
