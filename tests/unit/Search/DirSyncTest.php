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

namespace Tests\Unit\FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Control\Ad\DirSyncRequestControl;
use FreeDSx\Ldap\Control\Ad\DirSyncResponseControl;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\DirSync;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Constraint\Constraint;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Rule\InvocationOrder;
use PHPUnit\Framework\TestCase;
use Tests\Unit\FreeDSx\Ldap\TestFactoryTrait;

final class DirSyncTest extends TestCase
{
    use TestFactoryTrait;

    private LdapMessageResponse $initialResponse;

    private LdapMessageResponse $secondResponse;

    private DirSync $subject;

    private LdapClient&MockObject $client;

    protected function setUp(): void
    {
        $this->client = $this->createMock(LdapClient::class);

        $this->initialResponse = $this::makeSearchResponseFromEntries(
            entries: new Entries(),
            messageId: 0,
            controls: [new DirSyncResponseControl(1, 0, 'foo')],
        );
        $this->secondResponse = $this::makeSearchResponseFromEntries(
            entries: new Entries(),
            controls: [new DirSyncResponseControl(0, 0, 'fbar')],
        );

        $this->client
            ->expects($this->any())
            ->method('readOrFail')
            ->willReturn(
                new Entry(
                    '',
                    new Attribute(
                        'defaultNamingContext',
                        'dc=foo,dc=bar')
                )
            );

        $this->subject = new DirSync($this->client);
    }

    public function test_it_should_set_the_naming_context(): void
    {
        $this->addSendExpectation($this->callback(
            fn (SearchRequest $search) => $search->getBaseDn()?->toString() == 'dc=foo')
        );

        $this->subject->useNamingContext('dc=foo');

        $this->subject->getChanges();
    }

    public function test_it_should_set_the_filter(): void
    {
        $this->addSendExpectation($this->callback(
            fn (SearchRequest $search) => $search->getFilter()->toString() == '(foo=bar)'
        ));

        $this->subject->useFilter(Filters::equal(
            'foo',
            'bar'
        ));

        $this->subject->getChanges();
    }

    public function test_it_should_set_the_attributes_to_select(): void
    {
        $this->addSendExpectation($this->callback(
            fn (SearchRequest $search) => $search->getAttributes()[0]->getName() == 'foo'
        ));

        $this->subject->selectAttributes('foo');

        $this->subject->getChanges();
    }

    public function test_it_should_set_the_incremental_values_flag(): void
    {
        $this->addSendExpectation(
            $this->anything(),
            $this->callback(
                fn ($control) => $control instanceof DirSyncRequestControl
                    && $control->getFlags() !== DirSyncRequestControl::FLAG_INCREMENTAL_VALUES,
            ),
        );

        $this->subject->useIncrementalValues(false);

        $this->subject->getChanges();
    }

    public function test_it_should_object_security_flag(): void
    {
        $this->addSendExpectation(
            $this->anything(),
            $this->callback(
                fn ($control) => $control instanceof DirSyncRequestControl
                    && $control->getFlags() !== DirSyncRequestControl::FLAG_OBJECT_SECURITY,
            )
        );

        $this->subject->useObjectSecurity();

        $this->subject->getChanges();
    }

    public function test_it_should_set_ancestor_first_order(): void
    {
        $this->addSendExpectation(
            $this->anything(),
            $this->callback(
                fn ($control) => $control instanceof DirSyncRequestControl
                    && $control->getFlags() & DirSyncRequestControl::FLAG_ANCESTORS_FIRST_ORDER,
            )
        );

        $this->subject->useAncestorFirstOrder();

        $this->subject->getChanges();
    }

    public function test_it_should_set_the_cookie(): void
    {
        $this->addSendExpectation(
            $this->anything(),
            $this->callback(
                fn ($control) => $control instanceof DirSyncRequestControl
                    && $control->getCookie() === 'foo',
            ),
        );

        $this->subject->useCookie('foo');

        $this->subject->getChanges();
    }

    public function test_it_should_get_the_cookie(): void
    {
        self::assertSame(
            '',
            $this->subject->getCookie(),
        );

        $this->addSendExpectation();

        $this->subject->getChanges();

        self::assertSame(
            'foo',
            $this->subject->getCookie(),
        );
    }

    public function test_it_should_set_the_cookie_from_the_response_after_the_initial_query(): void
    {
        $this->client
            ->expects($this->any())
            ->method('send')
            ->will($this->onConsecutiveCalls(
                $this->initialResponse,
                $this->secondResponse,
            ));

        $this->subject->getChanges();
        self::assertSame(
            'foo',
            $this->subject->getCookie(),
        );

        $this->subject->getChanges();
        self::assertSame(
            'fbar',
            $this->subject->getCookie(),
        );
    }

    public function test_it_should_check_the_root_dse_for_the_default_naming_context(): void
    {
        $this->addSendAndOrderExpectation($this->atMost(2));
        $this->client
            ->expects($this->atMost(1))
            ->method('readOrFail')
            ->willReturn(new Entry(
            '',
                new Attribute(
                    'defaultNamingContext',
                    'dc=foo,dc=bar')
            ));

        $this->subject->getChanges();
        $this->subject->getChanges();
    }

    public function test_it_should_not_check_the_root_dse_for_the_default_naming_context_if_it_was_provided(): void
    {
        $this->addSendExpectation();
        $this->client
            ->expects($this->never())
            ->method('readOrFail');

        $this->subject->useNamingContext('dc=foo');

        $this->subject->getChanges();
    }

    public function test_it_should_return_false_for_changes_if_no_queries_have_been_made_yet(): void
    {
        self::assertFalse($this->subject->hasChanges());
    }

    public function test_it_should_return_true_for_changes_if_the_dir_sync_control_indicates_there_are(): void
    {
        $this->addSendExpectation();

        $this->subject->getChanges();

        self::assertTrue($this->subject->hasChanges());
    }

    public function test_it_should_return_false_for_changes_if_the_dir_sync_control_indicates_there_are_none_left(): void
    {
        $this->client
            ->expects($this->any())
            ->method('send')
            ->will($this->onConsecutiveCalls(
                $this->initialResponse,
                $this->secondResponse,
            ));

        $this->subject->getChanges();
        $this->subject->getChanges();

        self::assertFalse($this->subject->hasChanges());
    }

    /**
     * @param Constraint ...$arguments
     */
    private function addSendExpectation(...$arguments): void {
        $this->client
            ->expects($this->once())
            ->method('send')
            ->with(...array_values($arguments))
            ->willReturn($this->initialResponse);
    }

    /**
     * @param Constraint ...$arguments
     */
    private function addSendAndOrderExpectation(
        InvocationOrder $order,
        ...$arguments
    ): void {
        $this->client
            ->expects($order)
            ->method('send')
            ->with(...array_values($arguments))
            ->willReturn($this->initialResponse);
    }
}
