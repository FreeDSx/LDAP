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

namespace Tests\Unit\FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\UrlParseException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\LdapUrlExtension;
use PHPUnit\Framework\TestCase;

class LdapUrlTest extends TestCase
{
    private LdapUrl $subject;

    protected function setUp(): void
    {
        $this->subject = new LdapUrl('foo');
    }

    public function test_it_should_have_a_string_representation(): void
    {
        self::assertSame(
            'ldap://foo/',
            (string) $this->subject
        );
    }

    public function test_it_should_parse_a_url_with_no_host_but_a_path(): void
    {
        self::assertEquals(
            LdapUrl::parse('ldap:///o=University%20of%20Michigan,c=US'),
            (new LdapUrl())->setDn('o=University of Michigan,c=US')
        );
    }

    public function test_it_should_generate_a_url_with_no_host_but_a_path(): void
    {
        $this->subject = new LdapUrl(null);
        $this->subject->setDn('o=University of Michigan,c=US');

        self::assertSame(
            'ldap:///o=University%20of%20Michigan,c=US',
            (string) $this->subject,
        );
    }

    public function test_it_should_parse_a_url_with_a_host_and_path_but_no_query_elements(): void
    {
        self::assertEquals(
            LdapUrl::parse('ldap://ldap1.example.net/o=University%20of%20Michigan,c=US'),
            (new LdapUrl('ldap1.example.net'))->setDn('o=University of Michigan,c=US')
        );
    }

    public function test_it_should_generate_a_url_with_a_host_and_path_but_no_query_elements(): void
    {
        $this->subject = new LdapUrl('ldap1.example.net');
        $this->subject->setDn('o=University of Michigan,c=US');

        self::assertSame(
            'ldap://ldap1.example.net/o=University%20of%20Michigan,c=US',
            (string) $this->subject,
        );
    }

    public function test_it_should_parse_a_url_with_a_host_path_and_attribute(): void
    {
        self::assertEquals(
            LdapUrl::parse('ldap://ldap1.example.net/o=University%20of%20Michigan,c=US?postalAddress'),
            (new LdapUrl('ldap1.example.net'))
                ->setDn('o=University of Michigan,c=US')
                ->setAttributes('postalAddress')
        );
    }

    public function test_it_should_generate_a_url_with_a_host_path_and_attribute(): void
    {
        $this->subject = new LdapUrl('ldap1.example.net');
        $this->subject->setDn('o=University of Michigan,c=US');
        $this->subject->setAttributes('postalAddress');

        self::assertSame(
            'ldap://ldap1.example.net/o=University%20of%20Michigan,c=US?postalAddress',
            (string) $this->subject,
        );
    }

    public function test_it_should_parse_a_url_with_a_host_port_path_scope_and_filter(): void
    {
        self::assertEquals(
            LdapUrl::parse('ldap://ldap1.example.net:6666/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)'),
            (new LdapUrl('ldap1.example.net'))
                ->setPort(6666)
                ->setDn('o=University of Michigan,c=US')
                ->setFilter('(cn=Babs Jensen)')
                ->setScope('sub')
        );
    }

    public function test_it_should_generate_a_url_with_a_host_port_path_scope_and_filter(): void
    {
        $this->subject = new LdapUrl('ldap1.example.net');
        $this->subject->setPort(6666);
        $this->subject->setDn('o=University of Michigan,c=US');
        $this->subject->setFilter('(cn=Babs Jensen)');
        $this->subject->setScope('sub');

        self::assertSame(
            'ldap://ldap1.example.net:6666/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)',
            (string) $this->subject,
        );
    }

    public function test_it_should_parse_a_url_with_a_host_path_single_scope_and_attribute(): void
    {
        self::assertEquals(
            LdapUrl::parse('ldap://ldap1.example.com/c=GB?objectClass?ONE'),
            (new LdapUrl('ldap1.example.com'))
                ->setDn('c=GB')
                ->setAttributes('objectClass')
                ->setScope('one')
        );
    }

    public function test_it_should_generate_a_url_with_a_host_path_single_scope_and_attribute(): void
    {
        $this->subject = new LdapUrl('ldap1.example.com');
        $this->subject->setDn('c=GB');
        $this->subject->setAttributes('objectClass');
        $this->subject->setScope('ONE');

        self::assertSame(
            'ldap://ldap1.example.com/c=GB?objectClass?one',
            (string) $this->subject,
        );
    }

    public function test_it_should_parse_a_url_with_a_percent_encoded_question_mark_in_the_path(): void
    {
        self::assertEquals(
            LdapUrl::parse('ldap://ldap2.example.com/o=Question%3f,c=US?mail'),
            (new LdapUrl('ldap2.example.com'))
                ->setDn('o=Question?,c=US')
                ->setAttributes('mail')
        );
    }

    public function test_it_should_generate_a_url_with_a_percent_encoded_question_mark_in_the_path(): void
    {
        $this->subject = new LdapUrl('ldap2.example.com');
        $this->subject->setDn('o=Question?,c=US');
        $this->subject->setAttributes('mail');

        self::assertSame(
            'ldap://ldap2.example.com/o=Question%3f,c=US?mail',
            (string) $this->subject,
        );
    }

    public function test_it_should_parse_a_url_with_percent_encoded_filter_that_was_hex_escaped(): void
    {
        self::assertEquals(
            LdapUrl::parse('ldap://ldap3.example.com/o=Babsco,c=US???(four-octet=%5c00%5c00%5c00%5c04)'),
            (new LdapUrl('ldap3.example.com'))
                ->setDn('o=Babsco,c=US')
                ->setFilter('(four-octet=\00\00\00\04)')
        );
    }

    public function test_it_should_generate_a_url_with_percent_encoded_filter_that_was_hex_escaped(): void
    {
        $this->subject = new LdapUrl('ldap3.example.com');
        $this->subject->setDn('o=Babsco,c=US');
        $this->subject->setFilter('(four-octet=\00\00\00\04)');

        self::assertSame(
            'ldap://ldap3.example.com/o=Babsco,c=US???(four-octet=%5c00%5c00%5c00%5c04)',
            (string) $this->subject,
        );
    }

    public function test_it_should_parse_a_url_with_extensions(): void
    {
        self::assertEquals(
            LdapUrl::parse('ldap:///??sub??e-bindname=cn=Manager%2cdc=example%2cdc=com'),
            (new LdapUrl(null))
                ->setScope('sub')
                ->setExtensions(new LdapUrlExtension('e-bindname', 'cn=Manager,dc=example,dc=com'))
        );
    }

    public function test_it_should_generate_a_url_with_extensions(): void
    {
        $this->subject = new LdapUrl(null);
        $this->subject->setScope('sub');
        $this->subject->setExtensions(new LdapUrlExtension('e-bindname', 'cn=Manager,dc=example,dc=com'));

        self::assertSame(
            'ldap:///??sub??e-bindname=cn=Manager%2cdc=example%2cdc=com',
            (string) $this->subject,
        );
    }

    public function test_it_should_parse_a_url_with_all_default_query_fields(): void
    {
        self::assertEquals(
            LdapUrl::parse('ldap://foo/????'),
            (new LdapUrl('foo'))
        );
        self::assertEquals(
            LdapUrl::parse('ldap:///????'),
            (new LdapUrl())
        );
    }

    public function test_it_should_set_the_port(): void
    {
        self::assertNull($this->subject->getPort());

        $this->subject->setPort(9001);

        self::assertSame(
            9001,
            $this->subject->getPort(),
        );
    }

    public function test_it_should_set_the_valid_scopes(): void
    {
        self::assertNull($this->subject->getScope());

        $this->subject->setScope('base');

        self::assertSame(
            'base',
            $this->subject->getScope(),
        );

        $this->subject->setScope('one');

        self::assertSame(
            'one',
            $this->subject->getScope(),
        );

        $this->subject->setScope('sub');

        self::assertSame(
            'sub',
            $this->subject->getScope(),
        );
    }

    public function test_it_should_reject_an_invalid_scope(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->subject->setScope('foo');
    }

    public function test_it_should_set_the_filter(): void
    {
        self::assertNull($this->subject->getFilter());

        $this->subject->setFilter('foo=bar');

        self::assertSame(
            'foo=bar',
            $this->subject->getFilter(),
        );
    }

    public function test_it_should_set_the_dn(): void
    {
        self::assertNull($this->subject->getDn());

        $this->subject->setDn('dc=foo');

        self::assertEquals(
            new Dn('dc=foo'),
            $this->subject->getDn(),
        );
    }

    public function test_it_should_set_the_attributes(): void
    {
        self::assertEmpty($this->subject->getAttributes());

        $this->subject->setAttributes('foo', 'bar');
        self::assertEquals(
            [
                new Attribute('foo'),
                new Attribute('bar')
            ],
            $this->subject->getAttributes(),
        );
    }

    public function test_it_should_set_the_host(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getHost(),
        );

        $this->subject->setHost('bar');

        self::assertSame(
            'bar',
            $this->subject->getHost(),
        );
    }

    public function test_it_should_set_whether_or_not_ssl_is_used(): void
    {
        self::assertFalse($this->subject->getUseSsl());

        $this->subject->setUseSsl(true);

        self::assertTrue($this->subject->getUseSsl());
    }

    public function test_it_should_throw_an_error_if_the_scheme_is_not_ldap(): void
    {
        $this->expectException(UrlParseException::class);

        LdapUrl::parse('https://foo/?');
    }

    public function test_it_should_throw_an_error_if_the_scheme_is_not_ldap_with_no_host(): void
    {
        $this->expectException(UrlParseException::class);

        LdapUrl::parse('https:///?');
    }

    public function test_it_should_throw_an_error_on_a_malformed_url(): void
    {
        $this->expectException(UrlParseException::class);

        LdapUrl::parse('ldap');
    }
}
