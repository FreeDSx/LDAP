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

namespace Tests\Unit\FreeDSx\Ldap\Ldif\Url;

use FreeDSx\Ldap\Exception\LdifUrlException;
use FreeDSx\Ldap\Ldif\Url\FileUrlResolver;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\TempFileUrlTrait;

final class FileUrlResolverTest extends TestCase
{
    use TempFileUrlTrait;

    private FileUrlResolver $subject;

    protected function setUp(): void
    {
        $this->subject = new FileUrlResolver();
    }

    public function test_it_reads_the_file_a_url_names(): void
    {
        self::assertSame(
            'contents',
            $this->subject->resolve($this->tempFileUrl('contents')),
        );
    }

    public function test_it_decodes_a_percent_escaped_path(): void
    {
        $url = $this->tempFileUrl('contents');
        $escaped = 'file://' . str_replace(
            '-',
            '%2D',
            substr($url, strlen('file://')),
        );

        self::assertSame(
            'contents',
            $this->subject->resolve($escaped),
        );
    }

    /**
     * RFC 8089 A.2 spells a Windows drive letter "file:///c:/dir/file", which the filesystem wants unslashed.
     */
    public function test_it_strips_the_slash_a_drive_letter_url_carries(): void
    {
        $this->expectException(LdifUrlException::class);
        $this->expectExceptionMessage('The file "C:/nope/missing.txt" does not exist');

        $this->subject->resolve('file:///C:/nope/missing.txt');
    }

    #[DataProvider('refusedUrlProvider')]
    public function test_it_refuses_a_url_it_cannot_resolve(
        string $url,
        string $expected,
    ): void {
        $this->expectException(LdifUrlException::class);
        $this->expectExceptionMessage($expected);

        $this->subject->resolve($url);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function refusedUrlProvider(): iterable
    {
        yield 'a scheme it does not handle' => [
            'https://example.com/x.jpg',
            'Only the "file://" scheme is resolved',
        ];
        yield 'no scheme at all' => [
            '/etc/passwd',
            'Only the "file://" scheme is resolved',
        ];
        yield 'a host component' => [
            'file://example.com/share/x.jpg',
            'A "file://" URL naming a host is not resolved',
        ];
        yield 'a path that does not exist' => [
            'file:///nope/missing.txt',
            'does not exist or cannot be read',
        ];
    }
}
