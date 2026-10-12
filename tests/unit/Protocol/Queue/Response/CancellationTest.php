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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue\Response;

use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\Cancellation;
use PHPUnit\Framework\TestCase;

final class CancellationTest extends TestCase
{
    private Cancellation $subject;

    private LdapMessageRequest $cancel;

    protected function setUp(): void
    {
        $this->subject = new Cancellation();
        $this->cancel = new LdapMessageRequest(
            3,
            new CancelRequest(2),
        );
    }

    public function test_a_cancel_the_producer_never_looked_at_is_unobserved(): void
    {
        $this->subject->offer($this->cancel);

        self::assertSame(
            $this->cancel,
            $this->subject->unobservedCancel(),
        );
    }

    public function test_a_cancel_the_producer_looked_at_is_observed(): void
    {
        $this->subject->offer($this->cancel);
        $this->subject->isSignalled();

        self::assertNull($this->subject->unobservedCancel());
    }

    public function test_an_abandon_is_never_an_unobserved_cancel(): void
    {
        $this->subject->offer(new LdapMessageRequest(
            3,
            new AbandonRequest(2),
        ));

        self::assertNull($this->subject->unobservedCancel());
    }

    public function test_offering_nothing_keeps_the_signal_already_held(): void
    {
        $this->subject->offer($this->cancel);
        $this->subject->offer(null);

        self::assertSame(
            $this->cancel,
            $this->subject->signal(),
        );
    }
}
