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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue\Budget;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\Queue\Budget\BudgetShare;
use FreeDSx\Ldap\Protocol\Queue\Budget\HeldResponse;
use FreeDSx\Ldap\Protocol\Queue\Budget\HeldResponses;
use FreeDSx\Ldap\Protocol\Queue\Budget\IdentityShare;
use FreeDSx\Ldap\Protocol\Queue\Budget\RequestBudget;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Resources\SystemResources;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Clock\CallbackSleeper;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class HeldResponsesTest extends TestCase
{
    private const LIMIT = 100_000;

    private RequestBudget $budget;

    private ServerAuthorization $authorization;

    private HeldResponses $subject;

    protected function setUp(): void
    {
        $this->budget = new RequestBudget(
            new CallbackSleeper(),
            $this->createMock(SystemResources::class),
        );
        $this->authorization = new ServerAuthorization(TestServerOptions::defaults());
        $this->subject = new HeldResponses(
            $this->budget,
            self::LIMIT,
            new IdentityShare(
                $this->authorization,
                self::LIMIT,
            ),
        );
    }

    public function test_a_response_is_counted_under_the_identity_the_connection_is_bound_as_when_it_starts(): void
    {
        $this->authorization->setToken(BindToken::fromDn('cn=user,dc=foo,dc=bar'));
        $entry = Entry::create('cn=user,dc=foo,dc=bar');

        $held = $this->subject->start();
        $held->hold($entry);

        self::assertSame(
            HeldResponse::estimate($entry),
            $this->budget->heldBy(new BudgetShare(
                'dn:cn=user,dc=foo,dc=bar',
                self::LIMIT,
            )),
        );
    }
}
