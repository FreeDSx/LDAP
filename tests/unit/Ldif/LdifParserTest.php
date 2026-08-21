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

namespace Tests\Unit\FreeDSx\Ldap\Ldif;

use FreeDSx\Ldap\Exception\LdifParseException;
use FreeDSx\Ldap\Ldif\LdifChanges;
use FreeDSx\Ldap\Ldif\Url\FileUrlResolver;
use Tests\Support\FreeDSx\Ldap\TempFileUrlTrait;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use PHPUnit\Framework\TestCase;

final class LdifParserTest extends TestCase
{
    use TempFileUrlTrait;

    public function test_it_parses_a_single_content_record_with_multi_valued_attributes(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=foo,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: foo\nsn: Bar\n",
        );

        self::assertCount(1, $result);
        $entry = $result->entries()[0];
        self::assertSame(
            'cn=foo,dc=example,dc=com',
            $entry->getDn()->toString(),
        );
        self::assertSame(
            ['top', 'person'],
            $entry->get('objectClass')?->getValues(),
        );
        self::assertSame(
            ['Bar'],
            $entry->get('sn')?->getValues(),
        );
    }

    public function test_it_groups_attribute_descriptions_that_differ_only_in_case(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=foo,dc=x\nobjectclass: top\nobjectClass: person\nOBJECTCLASS: organizationalPerson\ncn: foo\n",
        );

        self::assertSame(
            ['top', 'person', 'organizationalPerson'],
            $result->entries()[0]->get('objectClass')?->getValues(),
        );
    }

    public function test_it_groups_a_case_differing_description_in_a_change_record_too(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=foo,dc=x\nchangetype: add\nobjectclass: top\nobjectClass: person\ncn: foo\n",
        );

        /** @var AddRequest $request */
        $request = $result->requests()[0];

        self::assertSame(
            ['top', 'person'],
            $request->getEntry()->get('objectClass')?->getValues(),
        );
    }

    public function test_it_keeps_descriptions_apart_when_their_options_differ(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=foo,dc=x\nmail: a@b.c\nMAIL;lang-en: d@e.f\nmail;LANG-EN: g@h.i\n",
        );
        $entry = $result->entries()[0];

        self::assertSame(
            ['a@b.c'],
            $entry->get('mail')?->getValues(),
        );
        self::assertSame(
            ['d@e.f', 'g@h.i'],
            $entry->get('mail;lang-en')?->getValues(),
        );
    }

    public function test_it_parses_multiple_records_separated_by_blank_lines(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=a,dc=x\ncn: a\n\ndn: cn=b,dc=x\ncn: b\n",
        );

        self::assertCount(
            2,
            $result,
        );
    }

    public function test_it_unfolds_continued_lines(): void
    {
        $entry = LdifChanges::fromString(
            "dn: cn=foo,dc=x\ndescription: this is a long\n  description value\n",
        )->entries()[0];

        self::assertSame(
            ['this is a long description value'],
            $entry->get('description')?->getValues(),
        );
    }

    public function test_it_decodes_a_base64_value(): void
    {
        $entry = LdifChanges::fromString(
            "dn: cn=foo,dc=x\ncn:: " . base64_encode('Bär') . "\n",
        )->entries()[0];

        self::assertSame(
            ['Bär'],
            $entry->get('cn')?->getValues(),
        );
    }

    public function test_it_decodes_a_base64_dn(): void
    {
        $entry = LdifChanges::fromString(
            "dn:: " . base64_encode('cn=Bär,dc=x') . "\ncn: x\n",
        )->entries()[0];

        self::assertSame(
            'cn=Bär,dc=x',
            $entry->getDn()->toString(),
        );
    }

    public function test_it_skips_comments_including_folded_ones(): void
    {
        $result = LdifChanges::fromString(
            "# a top comment\ndn: cn=foo,dc=x\n# inline comment\n# folded\n more comment\ncn: foo\n",
        );

        self::assertCount(1, $result);
        self::assertSame(
            ['foo'],
            $result->entries()[0]->get('cn')?->getValues(),
        );
    }

    public function test_it_accepts_a_version_one_header(): void
    {
        self::assertCount(
            1,
            LdifChanges::fromString("version: 1\ndn: cn=foo,dc=x\ncn: foo\n"),
        );
    }

    public function test_it_rejects_an_unsupported_version(): void
    {
        $this->expectException(LdifParseException::class);

        LdifChanges::fromString("version: 2\ndn: cn=foo,dc=x\ncn: foo\n");
    }

    public function test_it_rejects_a_version_after_a_record(): void
    {
        $this->expectException(LdifParseException::class);

        LdifChanges::fromString("dn: cn=foo,dc=x\ncn: foo\n\nversion: 1\n");
    }

    public function test_it_parses_a_mixed_file_with_content_and_change_records(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=foo,dc=x\ncn: foo\nsn: Bar\n"
            . "\n"
            . "dn: cn=baz,dc=x\nchangetype: modify\nreplace: sn\nsn: Quux\n-\n",
        );

        self::assertCount(2, $result);
        self::assertInstanceOf(
            AddRequest::class,
            $result->requests()[0],
        );
        self::assertInstanceOf(
            ModifyRequest::class,
            $result->requests()[1],
        );
    }

    public function test_it_rejects_url_referenced_values_when_no_resolver_is_configured(): void
    {
        $this->expectException(LdifParseException::class);
        $this->expectExceptionMessage('URL-referenced');

        LdifChanges::fromString("dn: cn=foo,dc=x\njpegPhoto:< file:///tmp/x.jpg\n");
    }

    public function test_it_reads_a_url_referenced_value_through_the_resolver_it_was_given(): void
    {
        $url = $this->tempFileUrl('photo-bytes');

        $result = LdifChanges::fromString(
            "dn: cn=foo,dc=x\ncn: foo\njpegPhoto:< $url\n",
            urlResolver: new FileUrlResolver(),
        );

        self::assertSame(
            'photo-bytes',
            $result->entries()[0]->get('jpegPhoto')?->firstValue(),
        );
    }

    public function test_it_reports_the_line_when_the_resolver_refuses_the_url(): void
    {
        $this->expectException(LdifParseException::class);
        $this->expectExceptionMessage('Only the "file://" scheme is resolved');

        LdifChanges::fromString(
            "dn: cn=foo,dc=x\njpegPhoto:< https://example.com/x.jpg\n",
            urlResolver: new FileUrlResolver(),
        );
    }

    public function test_it_reports_the_line_number_of_a_malformed_line(): void
    {
        try {
            LdifChanges::fromString("dn: cn=foo,dc=x\ncn: foo\nthis-has-no-colon\n");
            self::fail('Expected an LdifParseException.');
        } catch (LdifParseException $e) {
            self::assertSame(3, $e->getLineNumber());
            self::assertSame(
                'this-has-no-colon',
                $e->getSourceLine(),
            );
        }
    }

    public function test_it_parses_an_empty_value(): void
    {
        $entry = LdifChanges::fromString("dn: cn=foo,dc=x\ndescription:\n")->entries()[0];

        self::assertSame(
            [''],
            $entry->get('description')?->getValues(),
        );
    }

    public function test_it_returns_no_records_for_empty_input(): void
    {
        self::assertCount(0, LdifChanges::fromString(''));
    }
}
