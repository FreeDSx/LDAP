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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerRootDseHandler;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluator;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerRootDseHandlerTest extends TestCase
{
    private ServerRootDseHandler $subject;

    private TokenInterface&MockObject $mockToken;

    private ServerOptions $options;

    private LdapBackendInterface&MockObject $mockBackend;

    protected function setUp(): void
    {
        $this->options = new ServerOptions();
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->withBackendNamingContexts([]);
    }

    public function test_it_should_send_back_a_RootDSE(): void
    {
        $this->options->setDseVendorName('Foo');
        $this->withBackendNamingContexts(['dc=Foo,dc=Bar']);

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope(),
        );

        $stream = $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );

        $this->assertEquals(
            [
                new LdapMessageResponse(1, new SearchResultEntry(Entry::create('', [
                    'objectClass' => ['top'],
                    'namingContexts' => 'dc=Foo,dc=Bar',
                    'subschemaSubentry' => ['cn=Subschema'],
                    'supportedControl' => [
                        Control::OID_PAGING,
                        Control::OID_SORTING,
                        Control::OID_RELAX_RULES,
                        Control::OID_PROXY_AUTHORIZATION,
                        Control::OID_MANAGE_DSA_IT,
                        Control::OID_ASSERTION,
                        Control::OID_PRE_READ,
                        Control::OID_POST_READ,
                        Control::OID_SUBTREE_DELETE,
                    ],
                    'supportedExtension' => [
                        ExtendedRequest::OID_WHOAMI,
                        ExtendedRequest::OID_PWD_MODIFY,
                        ExtendedRequest::OID_CANCEL,
                    ],
                    'supportedFeatures' => [
                        '1.3.6.1.4.1.4203.1.5.1',
                        '1.3.6.1.4.1.4203.1.5.3',
                    ],
                    'supportedLDAPVersion' => ['3'],
                    'vendorName' => 'Foo',
                ]))),
                new LdapMessageResponse(1, new SearchResultDone(0)),
            ],
            [...$stream->messages],
        );
    }

    public function test_it_always_advertises_paging_and_password_modify(): void
    {
        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope(),
        );

        $stream = $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
        $messages = [...$stream->messages];

        /** @var SearchResultEntry $result */
        $result = $messages[0]->getResponse();
        $entry = $result->getEntry();

        self::assertTrue($entry->get('supportedControl')?->has(Control::OID_PAGING) === true);
        self::assertTrue($entry->get('supportedExtension')?->has(ExtendedRequest::OID_PWD_MODIFY) === true);
    }

    public function test_it_advertises_the_sync_control_when_sync_is_enabled(): void
    {
        $this->subject = new ServerRootDseHandler(
            $this->options,
            $this->mockBackend,
            new FilterEvaluator($this->options->getSchema()),
            true,
        );

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope(),
        );

        $stream = $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
        $messages = [...$stream->messages];

        /** @var SearchResultEntry $result */
        $result = $messages[0]->getResponse();

        self::assertTrue($result->getEntry()->get('supportedControl')?->has(Control::OID_SYNC_REQUEST) === true);
    }

    public function test_it_should_include_supported_sasl_mechanisms_when_configured(): void
    {
        $this->options
            ->setSaslMechanisms(ServerOptions::SASL_PLAIN, ServerOptions::SASL_CRAM_MD5);

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope(),
        );

        $stream = $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
        $messages = [...$stream->messages];

        /** @var SearchResultEntry $result */
        $result = $messages[0]->getResponse();
        $attribute = $result->getEntry()->get('supportedSaslMechanisms');

        self::assertNotNull($attribute);
        self::assertTrue($attribute->has(ServerOptions::SASL_PLAIN));
        self::assertTrue($attribute->has(ServerOptions::SASL_CRAM_MD5));
        self::assertEquals(
            new LdapMessageResponse(
                1,
                new SearchResultDone(0),
            ),
            $messages[1],
        );
    }

    public function test_it_should_only_return_attribute_names_from_the_RootDSE_if_requested(): void
    {
        $this->options->setDseVendorName('Foo');
        $this->withBackendNamingContexts(['dc=Foo,dc=Bar']);

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))
                ->base('')
                ->useBaseScope()
                ->setAttributesOnly(true),
        );

        $stream = $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );

        $this->assertEquals(
            [
                new LdapMessageResponse(1, new SearchResultEntry(Entry::create('', [
                    'objectClass' => [],
                    'namingContexts' => [],
                    'subschemaSubentry' => [],
                    'supportedControl' => [],
                    'supportedExtension' => [],
                    'supportedFeatures' => [],
                    'supportedLDAPVersion' => [],
                    'vendorName' => [],
                ]))),
                new LdapMessageResponse(1, new SearchResultDone(0)),
            ],
            [...$stream->messages],
        );
    }

    public function test_it_advertises_subschema_subentry_in_rootdse(): void
    {
        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope(),
        );

        $stream = $this->subject->handleRequest($search, $this->mockToken);
        $messages = [...$stream->messages];

        /** @var SearchResultEntry $result */
        $result = $messages[0]->getResponse();
        $attr = $result->getEntry()->get('subschemaSubentry');

        self::assertNotNull($attr);
        self::assertTrue($attr->has('cn=Subschema'));
    }

    public function test_it_uses_configured_subschema_entry_dn(): void
    {
        $this->options->getSchemaConfig()
            ->setSubschemaEntry(new Dn('cn=schema,dc=example,dc=com'));

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope(),
        );

        $stream = $this->subject->handleRequest($search, $this->mockToken);
        $messages = [...$stream->messages];

        /** @var SearchResultEntry $result */
        $result = $messages[0]->getResponse();
        $attr = $result->getEntry()->get('subschemaSubentry');

        self::assertNotNull($attr);
        self::assertTrue($attr->has('cn=schema,dc=example,dc=com'));
    }

    public function test_it_should_only_return_specific_attributes_from_the_RootDSE_if_requested(): void
    {
        $this->options->setDseVendorName('Foo');
        $this->withBackendNamingContexts(['dc=Foo,dc=Bar']);

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))
                ->base('')
                ->useBaseScope()
                ->setAttributes('namingcontexts'),
        );

        # The reset below is needed, unfortunately, to properly test due to how the objects change...
        # objectClass is built first and then dropped, which is what leaves namingContexts at its index.
        $entry = Entry::create('', [
            'objectClass' => 'top',
            'namingContexts' => 'dc=Foo,dc=Bar',
        ]);
        $entry->reset('objectClass');
        $entry->changes()->reset();
        $entry->get('namingContexts')?->equals(new Attribute('foo'));

        $stream = $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );

        $this->assertEquals(
            [
                new LdapMessageResponse(
                    1,
                    new SearchResultEntry($entry),
                ),
                new LdapMessageResponse(1, new SearchResultDone(0)),
            ],
            [...$stream->messages],
        );
    }

    /**
     * @param list<string> $dns
     */
    private function withBackendNamingContexts(array $dns): void
    {
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
        $this->mockBackend
            ->method('namingContexts')
            ->willReturn(array_map(
                fn(string $dn): Dn => new Dn($dn),
                $dns,
            ));

        $this->subject = new ServerRootDseHandler(
            $this->options,
            $this->mockBackend,
            new FilterEvaluator($this->options->getSchema()),
        );
    }
}
