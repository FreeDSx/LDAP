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

namespace Tests\Support\FreeDSx\Ldap;

use PHPUnit\Framework\Attributes\After;

use function file_put_contents;
use function str_replace;
use function str_starts_with;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

/**
 * Backs a temporary file with the RFC 8089 URL naming it, which differs by platform.
 */
trait TempFileUrlTrait
{
    /**
     * @var list<string>
     */
    private array $tempFileUrlPaths = [];

    #[After]
    protected function removeTempFileUrls(): void
    {
        foreach ($this->tempFileUrlPaths as $path) {
            @unlink($path);
        }

        $this->tempFileUrlPaths = [];
    }

    /**
     * Windows hands back "C:\dir\file", which RFC 8089 A.2 spells "file:///C:/dir/file".
     */
    private function tempFileUrl(string $contents): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'ldif-url-');
        file_put_contents($path, $contents);
        $this->tempFileUrlPaths[] = $path;

        $urlPath = str_replace('\\', '/', $path);

        return 'file://' . (str_starts_with($urlPath, '/') ? '' : '/') . $urlPath;
    }
}
