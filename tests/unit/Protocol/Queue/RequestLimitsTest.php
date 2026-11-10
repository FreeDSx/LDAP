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
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\Queue\RequestLimits;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\ManagerToken;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class RequestLimitsTest extends TestCase
{
    private ServerAuthorization $authorization;

    private RequestLimits $subject;

    protected function setUp(): void
    {
        $this->authorization = new ServerAuthorization(TestServerOptions::defaults());
        $this->subject = new RequestLimits(
            authorization: $this->authorization,
            maxSize: 1_024,
            maxAnonymousSize: 256,
            maxElements: 50,
        );
    }

    public function testItHoldsASessionWithoutABindToTheAnonymousSize(): void
    {
        self::assertSame(
            256,
            $this->subject->maxSize(),
        );
    }

    public function testItHoldsASessionWithoutABindToTheAnonymousSizeWhenAuthenticationIsNotRequired(): void
    {
        $limits = new RequestLimits(
            authorization: new ServerAuthorization(TestServerOptions::defaults()->setRequireAuthentication(false)),
            maxSize: 1_024,
            maxAnonymousSize: 256,
        );

        self::assertSame(
            256,
            $limits->maxSize(),
        );
    }

    public function testItHoldsASessionBoundWithCredentialsToTheFullSize(): void
    {
        $this->authorization->setToken(new BindToken(AuthzId::fromDn(new Dn('cn=user,dc=foo,dc=bar'))));

        self::assertSame(
            1_024,
            $this->subject->maxSize(),
        );
    }

    public function testItHoldsASessionBoundAsTheManagerToTheFullSize(): void
    {
        $this->authorization->setToken(new ManagerToken(new Dn('cn=manager')));

        self::assertSame(
            1_024,
            $this->subject->maxSize(),
        );
    }

    public function testItReturnsASessionToTheAnonymousSizeWhenItsBindIsReset(): void
    {
        $this->authorization->setToken(new BindToken(AuthzId::fromDn(new Dn('cn=user,dc=foo,dc=bar'))));
        $this->authorization->setToken(new AnonToken());

        self::assertSame(
            256,
            $this->subject->maxSize(),
        );
    }

    public function testAnAnonymousSizeOfZeroLeavesTheFullSize(): void
    {
        $limits = new RequestLimits(
            authorization: $this->authorization,
            maxSize: 1_024,
        );

        self::assertSame(
            1_024,
            $limits->maxSize(),
        );
    }

    public function testAFullSizeOfZeroLeavesTheAnonymousSize(): void
    {
        $limits = new RequestLimits(
            authorization: $this->authorization,
            maxAnonymousSize: 256,
        );

        self::assertSame(
            256,
            $limits->maxSize(),
        );
    }

    public function testAnAnonymousSizeAboveTheFullSizeIsHeldToTheFullSize(): void
    {
        $limits = new RequestLimits(
            authorization: $this->authorization,
            maxSize: 1_024,
            maxAnonymousSize: 4_096,
        );

        self::assertSame(
            1_024,
            $limits->maxSize(),
        );
    }

    public function testItHoldsTheNextRequestToTheSessionsSizeAndTheElementLimit(): void
    {
        self::assertEquals(
            new EncoderOptions(
                maxLength: 256,
                maxElements: 50,
            ),
            $this->subject->encoderOptions(),
        );
    }

    public function testItSetsNoLimitsByDefault(): void
    {
        self::assertEquals(
            new EncoderOptions(),
            (new RequestLimits($this->authorization))->encoderOptions(),
        );
    }

    public function testItLeavesTheNestedPartsWhatTheMainDecodeDidNotUse(): void
    {
        self::assertSame(
            30,
            $this->subject->elementsLeftAfter(20),
        );
    }

    public function testItSetsNoLimitOnTheNestedPartsWhenElementsAreUnlimited(): void
    {
        self::assertNull((new RequestLimits($this->authorization))->elementsLeftAfter(20));
    }
}
