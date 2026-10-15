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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The limits a search is held to, and the range each of its parameters must fall in.
 */
trait SearchLimitTestsTrait
{
    /**
     * A supertype the index cannot answer, so every candidate reaches the evaluator the limit counts.
     */
    public function testAFilterEvaluatedInPhpTripsTheLookthroughLimit(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--seed-entries=10',
                '--max-search-lookthrough=3',
            ],
        );
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->ldapClient()->search(
            Operations::search(Filters::equal('name', 'no-entry-has-this'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
    }

    public function testAnIndexAnsweredFilterAlsoTripsTheLookthroughLimit(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--seed-entries=10',
                '--max-search-lookthrough=3',
            ],
        );
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->ldapClient()->search(
            Operations::search(Filters::equal('sn', 'Seeded'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
    }

    /**
     * RFC 4511 4.5.1 constrains these fields, and the decoder only checks their type, so an out-of-range value
     * would otherwise be coerced into a request the client never made.
     *
     * @return iterable<string, array{SearchRequest}>
     */
    public static function outOfRangeSearchParameterProvider(): iterable
    {
        yield 'a scope above the enumeration' => [
            self::rangeProbeRequest()->setScope(3),
        ];
        yield 'a negative scope' => [
            self::rangeProbeRequest()->setScope(-1),
        ];
        yield 'an alias value above the enumeration' => [
            self::rangeProbeRequest()->setDereferenceAliases(4),
        ];
        yield 'a negative size limit' => [
            self::rangeProbeRequest()->setSizeLimit(-1),
        ];
        yield 'a negative time limit' => [
            self::rangeProbeRequest()->setTimeLimit(-1),
        ];
    }

    #[DataProvider('outOfRangeSearchParameterProvider')]
    public function test_a_search_parameter_outside_its_range_is_a_protocol_error(SearchRequest $request): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->ldapClient()->search($request);
    }

    /**
     * The clamp is applied with min(), so a negative limit would win it and lift the ceiling entirely.
     */
    public function testANegativeSizeLimitCannotDefeatTheServerMaximum(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--seed-entries=10',
                '--max-search-size=2',
            ],
        );
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setSizeLimit(-1),
        );
    }

    /**
     * A filter the backend answers exactly is still bounded by the handler, which needs one match past the limit.
     */
    public function testAnExactlyAnswerableFilterSignalsSizeLimitOverflow(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--seed-entries=10',
            ],
        );
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::SIZE_LIMIT_EXCEEDED);

        $this->ldapClient()->search(
            Operations::search(Filters::equal('sn', 'Seeded'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setSizeLimit(3),
        );
    }

    public function testAnExactlyAnswerableFilterWithinTheSizeLimitReturnsEveryMatch(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--seed-entries=10',
            ],
        );
        $this->authenticateUser();

        self::assertCount(
            10,
            $this->ldapClient()->search(
                Operations::search(Filters::equal('sn', 'Seeded'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope()
                    ->setSizeLimit(10),
            ),
        );
    }

    private static function rangeProbeRequest(): SearchRequest
    {
        return Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar');
    }
}
