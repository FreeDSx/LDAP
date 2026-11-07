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

namespace Tests\Support\FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use RuntimeException;

use function array_fill;
use function file_get_contents;
use function hex2bin;
use function is_array;
use function json_decode;

use const JSON_THROW_ON_ERROR;

/**
 * Wire PDUs for each request and response shape, paired with the outcome each one decoded to when recorded.
 *
 * @phpstan-type Row array{pdu: string, outcome: string}
 * @phpstan-type Rows array<string, Row>
 * @phpstan-type Fixture array{requests: Rows, responses: Rows, built: array<string, string>}
 */
final class DecodeBaseline
{
    private const FIXTURE = __DIR__ . '/../../resources/protocol/decode-baseline.json';

    /**
     * @return array<string, array{string, string}>
     */
    public static function requests(): array
    {
        $fixture = self::fixture();
        $cases = self::fromHex($fixture['requests']);

        foreach (self::builtRequests() as $name => $ber) {
            $cases[$name] = [
                $ber,
                $fixture['built'][$name] ?? throw new RuntimeException("No recorded outcome for \"{$name}\"."),
            ];
        }

        return $cases;
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function responses(): array
    {
        return self::fromHex(self::fixture()['responses']);
    }

    /**
     * The PDUs too large to keep as hex, built in code.
     *
     * @return array<string, string>
     */
    public static function builtRequests(): array
    {
        return [
            'filter: 30 levels of nesting' => self::search(self::nested(30)),
            'filter: 31 levels of nesting' => self::search(self::nested(31)),
            'filter: 1,000 items' => self::search(self::wideOr(1000)),
            'filter: 1,001 items' => self::search(self::wideOr(1001)),
            'filter: a substring counts once per part' => self::search(self::wideOr(
                999,
                self::substring(),
            )),
            'control: assertion has a budget of its own' => self::search(
                self::wideOr(1000),
                self::assertion(self::wideOr(1000)),
            ),
            'control: assertion with 1,001 items' => self::search(
                self::present(),
                self::assertion(self::wideOr(1001)),
            ),
        ];
    }

    /**
     * @return Fixture
     */
    private static function fixture(): array
    {
        $contents = file_get_contents(self::FIXTURE);
        if ($contents === false) {
            throw new RuntimeException('The decode baseline fixture could not be read.');
        }
        $fixture = json_decode(
            $contents,
            true,
            flags: JSON_THROW_ON_ERROR,
        );
        if (!is_array($fixture)) {
            throw new RuntimeException('The decode baseline fixture is malformed.');
        }

        /**
         * @var Fixture $fixture
         */
        return $fixture;
    }

    /**
     * @param Rows $rows
     * @return array<string, array{string, string}>
     */
    private static function fromHex(array $rows): array
    {
        $cases = [];
        foreach ($rows as $name => $row) {
            $cases[$name] = [
                (string) hex2bin($row['pdu']),
                $row['outcome'],
            ];
        }

        return $cases;
    }

    /**
     * @param AbstractType<mixed> $filter
     * @param AbstractType<mixed> ...$controls
     */
    private static function search(
        AbstractType $filter,
        AbstractType ...$controls,
    ): string {
        $message = Asn1::sequence(
            Asn1::integer(1),
            Asn1::application(
                3,
                Asn1::sequence(
                    Asn1::octetString('dc=foo,dc=bar'),
                    Asn1::enumerated(2),
                    Asn1::enumerated(0),
                    Asn1::integer(0),
                    Asn1::integer(0),
                    Asn1::boolean(false),
                    $filter,
                    Asn1::sequenceOf(),
                ),
            ),
        );
        if ($controls !== []) {
            $message->addChild(Asn1::context(
                0,
                Asn1::sequenceOf(...$controls),
            ));
        }

        return (new LdapEncoder())->encode($message);
    }

    /**
     * @return AbstractType<mixed>
     */
    private static function nested(int $levels): AbstractType
    {
        $filter = self::present();
        for ($i = 0; $i < $levels; $i++) {
            $filter = Asn1::context(
                0,
                Asn1::setOf($filter),
            );
        }

        return $filter;
    }

    /**
     * @param AbstractType<mixed> ...$extra
     * @return AbstractType<mixed>
     */
    private static function wideOr(
        int $items,
        AbstractType ...$extra,
    ): AbstractType {
        return Asn1::context(
            1,
            Asn1::setOf(
                ...array_fill(
                    0,
                    $items,
                    self::present(),
                ),
                ...$extra,
            ),
        );
    }

    /**
     * @return AbstractType<mixed>
     */
    private static function present(): AbstractType
    {
        return Asn1::context(
            7,
            Asn1::octetString('cn'),
        );
    }

    /**
     * @return AbstractType<mixed>
     */
    private static function substring(): AbstractType
    {
        return Asn1::context(
            4,
            Asn1::sequence(
                Asn1::octetString('cn'),
                Asn1::sequenceOf(
                    Asn1::context(
                        0,
                        Asn1::octetString('a'),
                    ),
                    Asn1::context(
                        2,
                        Asn1::octetString('z'),
                    ),
                ),
            ),
        );
    }

    /**
     * @param AbstractType<mixed> $filter
     * @return AbstractType<mixed>
     */
    private static function assertion(AbstractType $filter): AbstractType
    {
        return Asn1::sequence(
            Asn1::octetString(Control::OID_ASSERTION),
            Asn1::boolean(true),
            Asn1::octetString((new LdapEncoder())->encode($filter)),
        );
    }
}
