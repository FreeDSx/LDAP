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

namespace Tests\Unit\FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ReadEntry\PreReadControl;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Schema\AttributeTypeSpelling;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Middleware\AttributeTypeCanonicalizationMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\Middleware\RecordingMiddlewareHandler;

final class AttributeTypeCanonicalizationMiddlewareTest extends TestCase
{
    private AttributeTypeCanonicalizationMiddleware $subject;

    private RecordingMiddlewareHandler $next;

    protected function setUp(): void
    {
        $this->subject = new AttributeTypeCanonicalizationMiddleware(
            new AttributeTypeSpelling(SchemaResource::Core->load()),
        );
        $this->next = new RecordingMiddlewareHandler(new CallLog());
    }

    public function test_the_request_is_passed_on(): void
    {
        $this->subject->process(
            $this->contextFor(new DeleteRequest('cn=Alice,dc=example,dc=com')),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_an_add_entry_dn_and_attributes_are_respelled(): void
    {
        $request = new AddRequest(Entry::fromArray(
            'commonName=Alice,dc=example,dc=com',
            ['surname' => 'Smith'],
        ));

        $this->subject->process(
            $this->contextFor($request),
            $this->next,
        );

        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $request->getEntry()->getDn()->toString(),
        );
        self::assertSame(
            'sn',
            $request->getEntry()->getAttributes()[0]->getDescription(),
        );
    }

    public function test_a_modify_dn_and_changes_are_respelled(): void
    {
        $request = Operations::modify(
            '2.5.4.3=Alice,dc=example,dc=com',
            Change::replace(new Attribute('surname;lang-en', 'Smith')),
        );

        $this->subject->process(
            $this->contextFor($request),
            $this->next,
        );

        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $request->getDn()->toString(),
        );
        self::assertSame(
            'sn;lang-en',
            $request->getChanges()[0]->getAttribute()->getDescription(),
        );
    }

    public function test_a_rename_dn_new_rdn_and_new_parent_are_respelled(): void
    {
        $request = new ModifyDnRequest(
            'commonName=Alice,dc=example,dc=com',
            'commonName=Alicia+surname=Smith',
            true,
            'organizationalUnitName=People,dc=example,dc=com',
        );

        $this->subject->process(
            $this->contextFor($request),
            $this->next,
        );

        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $request->getDn()->toString(),
        );
        self::assertSame(
            'cn=Alicia+sn=Smith',
            $request->getNewRdn()->toString(),
        );
        self::assertSame(
            'ou=People,dc=example,dc=com',
            $request->getNewParentDn()?->toString(),
        );
    }

    public function test_a_delete_dn_is_respelled(): void
    {
        $request = new DeleteRequest('commonName=Alice,dc=example,dc=com');

        $this->subject->process(
            $this->contextFor($request),
            $this->next,
        );

        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $request->getDn()->toString(),
        );
    }

    public function test_a_compare_dn_is_respelled(): void
    {
        $request = Operations::compare(
            'commonName=Alice,dc=example,dc=com',
            'sn',
            'Smith',
        );

        $this->subject->process(
            $this->contextFor($request),
            $this->next,
        );

        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $request->getDn()->toString(),
        );
    }

    public function test_a_search_base_is_respelled(): void
    {
        $request = Operations::search(Filters::present('objectClass'))
            ->base('commonName=Alice,dc=example,dc=com');

        $this->subject->process(
            $this->contextFor($request),
            $this->next,
        );

        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $request->getBaseDn()?->toString(),
        );
    }

    public function test_a_simple_bind_name_is_respelled(): void
    {
        $request = Operations::bind(
            'commonName=Alice,dc=example,dc=com',
            'secret',
        );

        $this->subject->process(
            $this->contextFor($request),
            $this->next,
        );

        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $request->getUsername(),
        );
    }

    public function test_a_bind_name_that_is_not_a_dn_is_left_alone(): void
    {
        $request = Operations::bind(
            'alice@example.com',
            'secret',
        );

        $this->subject->process(
            $this->contextFor($request),
            $this->next,
        );

        self::assertSame(
            'alice@example.com',
            $request->getUsername(),
        );
    }

    public function test_a_compare_assertion_attribute_is_respelled(): void
    {
        $request = Operations::compare(
            'cn=Alice,dc=example,dc=com',
            'surname',
            'Smith',
        );

        $this->subject->process(
            $this->contextFor($request),
            $this->next,
        );

        self::assertSame(
            'sn',
            $request->getFilter()->getAttribute(),
        );
    }

    public function test_a_search_filter_and_requested_attributes_are_respelled(): void
    {
        $request = Operations::search(
            Filters::and(
                Filters::equal('surname', 'Smith'),
                Filters::not(Filters::present('commonName')),
            ),
            'surname;lang-en',
            '*',
        );

        $this->subject->process(
            $this->contextFor($request),
            $this->next,
        );

        self::assertSame(
            '(&(sn=Smith)(!(cn=*)))',
            $request->getFilter()->toString(),
        );
        self::assertSame(
            ['sn;lang-en', '*'],
            array_map(
                static fn(Attribute $attribute): string => $attribute->getDescription(),
                $request->getAttributes(),
            ),
        );
    }

    public function test_sort_keys_are_respelled(): void
    {
        $sorting = new SortingControl(SortKey::ascending('surname'));

        $this->subject->process(
            $this->contextFor(
                Operations::search(Filters::present('objectClass')),
                $sorting,
            ),
            $this->next,
        );

        self::assertSame(
            'sn',
            $sorting->getSortKeys()[0]->getAttribute(),
        );
    }

    public function test_an_assertion_control_filter_is_respelled(): void
    {
        $assertion = Controls::assertion(Filters::equal('surname', 'Smith'));

        $this->subject->process(
            $this->contextFor(
                new DeleteRequest('cn=Alice,dc=example,dc=com'),
                $assertion,
            ),
            $this->next,
        );

        self::assertSame(
            '(sn=Smith)',
            $assertion->getFilter()->toString(),
        );
    }

    public function test_a_read_entry_control_is_replaced_by_a_respelled_copy_keeping_its_criticality(): void
    {
        $context = $this->contextFor(
            new DeleteRequest('cn=Alice,dc=example,dc=com'),
            Controls::preRead('surname')->setCriticality(true),
        );

        $this->subject->process(
            $context,
            $this->next,
        );

        $preRead = $context->message->controls()->get(Control::OID_PRE_READ);
        self::assertInstanceOf(
            PreReadControl::class,
            $preRead,
        );
        self::assertSame(
            ['sn'],
            $preRead->getAttributes(),
        );
        self::assertTrue($preRead->getCriticality());
    }

    private function contextFor(
        RequestInterface $request,
        Control ...$controls,
    ): ServerRequestContext {
        return new ServerRequestContext(
            new LdapMessageRequest(
                1,
                $request,
                ...$controls,
            ),
            $this->createMock(TokenInterface::class),
        );
    }
}
