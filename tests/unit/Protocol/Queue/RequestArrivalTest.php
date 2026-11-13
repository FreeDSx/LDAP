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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue;

use FreeDSx\Asn1\Encoder\EncoderOptions;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\Queue\RequestArrival;
use FreeDSx\Ldap\Protocol\Queue\RequestLimits;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Socket\Exception\ReadTimeoutException;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class RequestArrivalTest extends TestCase
{
    private ServerAuthorization $authorization;

    protected function setUp(): void
    {
        $this->authorization = new ServerAuthorization(TestServerOptions::defaults());
    }

    public function test_it_holds_the_encoder_to_the_size_the_session_may_send(): void
    {
        $encoder = new LdapEncoder();

        $this->arrivalWith(maxSize: 1_000)->limitDecoding($encoder);

        self::assertEquals(
            new EncoderOptions(
                maxLength: 1_000,
                maxElements: 50,
            ),
            $encoder->getOptions(),
        );
    }

    public function test_it_leaves_the_encoder_alone_while_the_size_the_session_may_send_is_unchanged(): void
    {
        $encoder = $this->createMock(LdapEncoder::class);
        $encoder->expects(self::once())
            ->method('setOptions');
        $subject = $this->arrivalWith(maxSize: 1_000);

        $subject->limitDecoding($encoder);
        $subject->limitDecoding($encoder);
    }

    public function test_it_leaves_a_read_between_requests_to_the_idle_timeout(): void
    {
        self::assertNull($this->arrivalWith(readTimeout: 30)->readTimeout(false));
    }

    public function test_it_leaves_a_read_to_the_idle_timeout_without_a_read_timeout(): void
    {
        self::assertNull($this->arrivalWith(readTimeout: 0)->readTimeout(true));
    }

    public function test_a_request_that_has_begun_to_arrive_has_the_read_timeout_left_to_finish(): void
    {
        $subject = $this->arrivalWith(readTimeout: 30);

        $first = $subject->readTimeout(true);
        $second = $subject->readTimeout(true);

        self::assertGreaterThan(
            29.9,
            $first,
        );
        self::assertLessThanOrEqual(
            30.0,
            $first,
        );
        self::assertLessThanOrEqual(
            $first,
            $second,
        );
    }

    public function test_each_request_has_the_whole_read_timeout_to_arrive(): void
    {
        $subject = $this->arrivalWith(readTimeout: 30);
        $subject->readTimeout(true);
        usleep(50_000);

        $subject->arrived();

        self::assertGreaterThan(
            29.99,
            $subject->readTimeout(true),
        );
    }

    public function test_a_read_that_timed_out_is_reported_as_the_request_taking_too_long(): void
    {
        $timeout = new ReadTimeoutException('The read did not complete within its timeout of 30 seconds.');

        self::expectException(ReadTimeoutException::class);
        self::expectExceptionMessage('The request did not finish arriving within 30 seconds.');

        $this->arrivalWith(readTimeout: 30)->timedOut($timeout);
    }

    private function arrivalWith(
        int $maxSize = 0,
        int $readTimeout = 0,
    ): RequestArrival {
        return new RequestArrival(new RequestLimits(
            $this->authorization,
            maxSize: $maxSize,
            maxElements: 50,
            readTimeout: $readTimeout,
        ));
    }
}
