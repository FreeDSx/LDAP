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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Provider;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Sync\Provider\Exception\MalformedSyncCookieException;
use FreeDSx\Ldap\Sync\Provider\SyncCookie;
use PHPUnit\Framework\TestCase;

final class SyncCookieTest extends TestCase
{
    public function test_encode_decode_preserves_the_origin_and_seq(): void
    {
        $decoded = SyncCookie::decode(
            (new SyncCookie(new ReplicaId('node-a'), 42))->encode(),
        );

        self::assertTrue($decoded->origin->equals(new ReplicaId('node-a')));
        self::assertSame(
            42,
            $decoded->seq,
        );
    }

    public function test_a_zero_seq_round_trips(): void
    {
        $decoded = SyncCookie::decode(
            (new SyncCookie(new ReplicaId('node-a'), 0))->encode(),
        );

        self::assertSame(
            0,
            $decoded->seq,
        );
    }

    public function test_it_rejects_a_negative_seq(): void
    {
        self::expectException(InvalidArgumentException::class);

        new SyncCookie(
            new ReplicaId('node-a'),
            -1,
        );
    }

    public function test_decode_rejects_invalid_base64(): void
    {
        self::expectException(MalformedSyncCookieException::class);

        SyncCookie::decode('@@not base64@@');
    }

    public function test_decode_rejects_an_unsupported_version(): void
    {
        $future = base64_encode((string) json_encode([
            'v' => 99,
            'origin' => 'node-a',
            'seq' => 1,
        ]));

        self::expectException(MalformedSyncCookieException::class);

        SyncCookie::decode($future);
    }

    public function test_encode_decode_preserves_the_content_key(): void
    {
        $decoded = SyncCookie::decode(
            (new SyncCookie(new ReplicaId('node-a'), 1, 'abc123'))->encode(),
        );

        self::assertSame(
            'abc123',
            $decoded->content,
        );
    }

    public function test_decode_rejects_a_cookie_without_a_content_key(): void
    {
        $legacy = base64_encode((string) json_encode([
            'v' => 2,
            'origin' => 'node-a',
            'seq' => 1,
        ]));

        self::expectException(MalformedSyncCookieException::class);

        SyncCookie::decode($legacy);
    }

    public function test_the_content_key_changes_with_each_content_controlling_parameter(): void
    {
        $base = $this->request();

        $keys = [
            SyncCookie::contentKey($base),
            SyncCookie::contentKey($this->request()->base('ou=other,dc=example,dc=com')),
            SyncCookie::contentKey($this->request()->useSingleLevelScope()),
            SyncCookie::contentKey($this->request()->select('cn')),
            SyncCookie::contentKey($this->request()->setAttributesOnly(true)),
            SyncCookie::contentKey($this->request()->setDereferenceAliases(SearchRequest::DEREF_FINDING_BASE_OBJECT)),
            SyncCookie::contentKey(
                (new SearchRequest(Filters::equal('cn', 'a')))
                    ->base('dc=example,dc=com')
                    ->useSubtreeScope(),
            ),
        ];

        self::assertSame(
            $keys,
            array_unique($keys),
        );
    }

    public function test_the_content_key_ignores_the_limits(): void
    {
        self::assertSame(
            SyncCookie::contentKey($this->request()),
            SyncCookie::contentKey(
                $this->request()
                    ->setSizeLimit(10)
                    ->setTimeLimit(20),
            ),
        );
    }

    public function test_the_content_key_ignores_the_order_and_case_of_the_selection(): void
    {
        self::assertSame(
            SyncCookie::contentKey($this->request()->select('cn', 'SN')),
            SyncCookie::contentKey($this->request()->select('sn', 'CN')),
        );
    }

    private function request(): SearchRequest
    {
        return (new SearchRequest(Filters::present('objectClass')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
    }
}
