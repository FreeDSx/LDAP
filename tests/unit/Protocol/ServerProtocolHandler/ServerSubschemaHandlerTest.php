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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\GeneratedEntryResponder;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSubschemaHandler;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use Tests\Support\FreeDSx\Ldap\Backend\Storage\FilterEvaluatorFactoryTrait;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerSubschemaHandlerTest extends TestCase
{
    use FilterEvaluatorFactoryTrait;

    private TokenInterface&MockObject $mockToken;

    private ServerOptions $options;

    private ServerSubschemaHandler $subject;

    protected function setUp(): void
    {
        $this->options = new ServerOptions();
        $this->mockToken = $this->createMock(TokenInterface::class);

        $this->subject = new ServerSubschemaHandler(
            options: $this->options,
            responder: $this->responder($this->options->getSchema()),
        );
    }

    public function test_it_returns_a_stub_subschema_entry(): void
    {
        $stream = $this->subject->handleRequest($this->makeMessage(), $this->mockToken);
        $messages = [...$stream->messages];

        /** @var SearchResultEntry $result */
        $result = $messages[0]->getResponse();
        $entry = $result->getEntry();

        self::assertSame(
            'cn=Subschema',
            $entry->getDn()->toString(),
        );
        self::assertTrue($entry->get('objectClass')?->has('subschema') ?? false);
        self::assertTrue($entry->get('cn')?->has('Subschema') ?? false);
        self::assertEquals(
            new LdapMessageResponse(1, new SearchResultDone(ResultCode::SUCCESS)),
            $messages[1],
        );
    }

    public function test_it_uses_the_configured_subschema_entry_dn(): void
    {
        $this->options->getSchemaConfig()
            ->setSubschemaEntry(new Dn('cn=schema,dc=example,dc=com'));

        $entry = $this->handleAndCaptureEntry();

        self::assertSame(
            'cn=schema,dc=example,dc=com',
            $entry->getDn()->toString(),
        );
        self::assertTrue($entry->get('cn')?->has('schema') ?? false);
    }

    public function test_it_returns_non_empty_attribute_types_in_rfc4512_format(): void
    {
        $entry = $this->handleAndCaptureEntry('+');
        $values = $entry->get('attributeTypes')?->getValues() ?? [];

        self::assertGreaterThan(0, count($values));
        self::assertStringStartsWith('( ', $values[0]);
    }

    public function test_it_returns_non_empty_object_classes(): void
    {
        $entry = $this->handleAndCaptureEntry('+');

        self::assertGreaterThan(
            0,
            count($entry->get('objectClasses')?->getValues() ?? []),
        );
    }

    public function test_it_returns_non_empty_matching_rules(): void
    {
        $entry = $this->handleAndCaptureEntry('+');

        self::assertGreaterThan(
            0,
            count($entry->get('matchingRules')?->getValues() ?? []),
        );
    }

    public function test_it_returns_non_empty_ldap_syntaxes(): void
    {
        $entry = $this->handleAndCaptureEntry('+');

        self::assertGreaterThan(
            0,
            count($entry->get('ldapSyntaxes')?->getValues() ?? []),
        );
    }

    public function test_it_returns_non_empty_matching_rule_use(): void
    {
        $entry = $this->handleAndCaptureEntry('+');

        self::assertGreaterThan(
            0,
            count($entry->get('matchingRuleUse')?->getValues() ?? []),
        );
    }

    /**
     * The schema definitions are operational, so a client that did not ask for them gets the naming attributes only.
     */
    public function test_a_bare_read_returns_only_the_naming_attributes(): void
    {
        foreach ([[], ['*']] as $selectors) {
            $entry = $this->handleAndCaptureEntry(...$selectors);

            self::assertSame(
                ['objectClass', 'cn'],
                array_keys($entry->toArray()),
            );
        }
    }

    public function test_a_named_schema_attribute_is_returned_on_its_own(): void
    {
        $entry = $this->handleAndCaptureEntry('objectClasses');

        self::assertSame(
            ['objectClasses'],
            array_keys($entry->toArray()),
        );
    }

    private function responder(Schema $schema): GeneratedEntryResponder
    {
        return new GeneratedEntryResponder(
            new RuleBasedAccessControl(),
            $this->makeFilterEvaluator($schema),
            $schema,
        );
    }

    private function makeMessage(string ...$selectors): LdapMessageRequest
    {
        return new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))
                ->base($this->options->getSubschemaEntry()->toString())
                ->useBaseScope()
                ->setAttributes(...$selectors),
        );
    }

    private function handleAndCaptureEntry(string ...$selectors): Entry
    {
        $stream = $this->subject->handleRequest($this->makeMessage(...$selectors), $this->mockToken);
        $messages = [...$stream->messages];

        /** @var SearchResultEntry $result */
        $result = $messages[0]->getResponse();

        return $result->getEntry();
    }
}
