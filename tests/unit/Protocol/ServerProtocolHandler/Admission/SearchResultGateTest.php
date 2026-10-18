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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler\Admission;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\Admission\SearchResultGate;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AttributeProjection;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\ReloadableAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\StrippedEntryMatcher;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class SearchResultGateTest extends TestCase
{
    private Schema $schema;

    private FilterEvaluatorInterface&MockObject $mockEvaluator;

    private StrippedEntryMatcher $strippedMatcher;

    private BindToken $token;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Core->load();
        $this->mockEvaluator = $this->createMock(FilterEvaluatorInterface::class);
        $this->strippedMatcher = new StrippedEntryMatcher(
            $this->mockEvaluator,
            $this->schema,
            new LinkedAttributes($this->schema),
        );
        $this->token = BindToken::fromDn('cn=user,dc=foo,dc=bar');
    }

    public function test_an_entry_returned_whole_is_the_entry_itself(): void
    {
        $entry = $this->person('cn=a,dc=foo,dc=bar');

        self::assertSame(
            $entry,
            $this->gate($this->allowing())->admit($entry),
        );
    }

    public function test_an_entry_the_identity_may_not_see_is_not_returned(): void
    {
        $gate = $this->gate(new RuleBasedAccessControl(AclRules::fromEmpty(
            operations: [OperationRule::allow(
                Subject::anyone(),
                Target::subtree('ou=shown,dc=foo,dc=bar'),
            )],
        )));

        self::assertNull($gate->admit($this->person('cn=a,ou=hidden,dc=foo,dc=bar')));
        self::assertNotNull($gate->admit($this->person('cn=a,ou=shown,dc=foo,dc=bar')));
    }

    public function test_a_withheld_attribute_the_filter_does_not_read_is_left_out_without_judging_the_entry_again(): void
    {
        $this->mockEvaluator
            ->expects(self::never())
            ->method('evaluate');

        $returned = $this->gate($this->allowing(AttributeRule::deny(
            Subject::anyone(),
            Target::any(),
            'userPassword',
        )->forRead()))->admit($this->person('cn=a,dc=foo,dc=bar'));

        self::assertSame(
            ['cn', 'mail'],
            $this->descriptions($returned),
        );
    }

    public function test_an_entry_that_stops_matching_once_stripped_is_not_returned(): void
    {
        $this->mockEvaluator
            ->expects(self::once())
            ->method('evaluate')
            ->willReturn(false);

        $gate = $this->gate(
            $this->allowing(AttributeRule::deny(
                Subject::anyone(),
                Target::any(),
                'userPassword',
            )->forRead()),
            filter: Filters::present('userPassword'),
        );

        self::assertNull($gate->admit($this->person('cn=a,dc=foo,dc=bar')));
    }

    public function test_an_entry_that_still_matches_once_stripped_is_returned_without_what_was_withheld(): void
    {
        $this->mockEvaluator
            ->expects(self::once())
            ->method('evaluate')
            ->with(self::callback(static fn(Entry $stripped): bool => $stripped->get('userPassword') === null))
            ->willReturn(true);

        $gate = $this->gate(
            $this->allowing(AttributeRule::deny(
                Subject::anyone(),
                Target::any(),
                'userPassword',
            )->forRead()),
            filter: Filters::or(
                Filters::present('userPassword'),
                Filters::present('cn'),
            ),
        );

        self::assertSame(
            ['cn', 'mail'],
            $this->descriptions($gate->admit($this->person('cn=a,dc=foo,dc=bar'))),
        );
    }

    public function test_an_attribute_neither_returned_nor_read_by_the_filter_is_never_put_to_the_rules(): void
    {
        $consulted = 0;
        $gate = $this->gate(
            $this->allowing(AttributeRule::deny(
                Subject::callback(static function () use (&$consulted): bool {
                    $consulted++;

                    return false;
                }),
                Target::any(),
                'mail',
            )->forRead()),
            selected: [new Attribute('cn')],
        );

        $gate->admit($this->person('cn=a,dc=foo,dc=bar'));
        $gate->admit($this->person('cn=b,dc=foo,dc=bar'));

        self::assertSame(
            0,
            $consulted,
        );
    }

    public function test_a_decision_only_the_entry_can_make_is_made_for_each_entry(): void
    {
        $gate = $this->gate($this->allowing(AttributeRule::deny(
            Subject::anyone(),
            Target::subtree('ou=hidden,dc=foo,dc=bar'),
            'mail',
        )->forRead()));

        self::assertSame(
            ['cn', 'mail', 'userPassword'],
            $this->descriptions($gate->admit($this->person('cn=a,ou=shown,dc=foo,dc=bar'))),
        );
        self::assertSame(
            ['cn', 'userPassword'],
            $this->descriptions($gate->admit($this->person('cn=a,ou=hidden,dc=foo,dc=bar'))),
        );
    }

    public function test_an_option_bearing_form_is_decided_by_its_type(): void
    {
        $returned = $this->gate($this->allowing(AttributeRule::deny(
            Subject::anyone(),
            Target::any(),
            'mail',
        )->forRead()))->admit(new Entry(
            new Dn('cn=a,dc=foo,dc=bar'),
            new Attribute(
                'cn',
                'a',
            ),
            new Attribute(
                'Mail;lang-en',
                'a@foo.bar',
            ),
        ));

        self::assertSame(
            ['cn'],
            $this->descriptions($returned),
        );
    }

    public function test_a_types_only_request_returns_descriptions_without_values(): void
    {
        $returned = $this->gate(
            $this->allowing(),
            typesOnly: true,
        )->admit($this->person('cn=a,dc=foo,dc=bar'));

        self::assertNotNull($returned);

        foreach ($returned->getAttributes() as $attribute) {
            self::assertSame(
                [],
                $attribute->getValues(),
            );
        }
    }

    public function test_a_request_for_no_attributes_returns_only_the_dn(): void
    {
        $returned = $this->gate(
            $this->allowing(),
            selected: [new Attribute('1.1')],
        )->admit($this->person('cn=a,dc=foo,dc=bar'));

        self::assertSame(
            [],
            $this->descriptions($returned),
        );
        self::assertSame(
            'cn=a,dc=foo,dc=bar',
            $returned?->getDn()->toString(),
        );
    }

    public function test_a_reload_decides_the_entries_still_to_come(): void
    {
        $accessControl = new ReloadableAccessControl($this->allowing());
        $gate = $this->gate($accessControl);

        foreach (['cn=a,dc=foo,dc=bar', 'cn=b,dc=foo,dc=bar'] as $dn) {
            self::assertSame(
                ['cn', 'mail', 'userPassword'],
                $this->descriptions($gate->admit($this->person($dn))),
            );
        }

        $accessControl->replace($this->allowing(AttributeRule::deny(
            Subject::anyone(),
            Target::any(),
            'mail',
        )->forRead()));

        self::assertSame(
            ['cn', 'userPassword'],
            $this->descriptions($gate->admit($this->person('cn=c,dc=foo,dc=bar'))),
        );
    }

    /**
     * @param list<Attribute> $selected
     */
    private function gate(
        AccessControlInterface $accessControl,
        ?FilterInterface $filter = null,
        array $selected = [],
        bool $typesOnly = false,
    ): SearchResultGate {
        return SearchResultGate::forRequest(
            $accessControl,
            $this->strippedMatcher,
            AttributeProjection::forRequest(
                $selected,
                $typesOnly,
                $this->schema,
            ),
            $this->token,
            $filter ?? Filters::present('cn'),
        );
    }

    private function allowing(AttributeRule ...$rules): RuleBasedAccessControl
    {
        return new RuleBasedAccessControl(AclRules::fromEmpty(
            operations: [OperationRule::allow(Subject::anyone())],
            attributes: $rules,
        ));
    }

    private function person(string $dn): Entry
    {
        return new Entry(
            new Dn($dn),
            new Attribute(
                'cn',
                'a',
            ),
            new Attribute(
                'mail',
                'a@foo.bar',
            ),
            new Attribute(
                'userPassword',
                'secret',
            ),
        );
    }

    /**
     * @return list<string>
     */
    private function descriptions(?Entry $entry): array
    {
        return array_values(array_map(
            static fn(Attribute $attribute): string => $attribute->getDescription(),
            $entry?->getAttributes() ?? [],
        ));
    }
}
