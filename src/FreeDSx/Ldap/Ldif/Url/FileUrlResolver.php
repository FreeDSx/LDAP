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

namespace FreeDSx\Ldap\Ldif\Url;

use FreeDSx\Ldap\Exception\LdifUrlException;

use function file_get_contents;
use function is_file;
use function is_readable;
use function preg_match;
use function rawurldecode;
use function sprintf;
use function str_starts_with;
use function strlen;
use function substr;

/**
 * Resolves only the file scheme, so enabling URL values cannot reach the network.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class FileUrlResolver implements LdifUrlResolverInterface
{
    private const SCHEME = 'file://';

    public function resolve(string $url): string
    {
        if (!str_starts_with($url, self::SCHEME)) {
            throw new LdifUrlException(sprintf('Only the "file://" scheme is resolved, got "%s"', $url));
        }
        $path = rawurldecode(substr($url, strlen(self::SCHEME)));

        // A host component is legal in the syntax but names something this resolver cannot reach.
        if ($path !== '' && !str_starts_with($path, '/')) {
            throw new LdifUrlException(sprintf('A "file://" URL naming a host is not resolved, got "%s"', $url));
        }

        // RFC 8089 A.2 spells a drive letter as "/c:/path", which the filesystem wants without the slash.
        if (preg_match('#^/[A-Za-z]:(?:[/\\\\]|$)#', $path) === 1) {
            $path = substr($path, 1);
        }
        if (!is_file($path) || !is_readable($path)) {
            throw new LdifUrlException(sprintf('The file "%s" does not exist or cannot be read', $path));
        }
        $contents = file_get_contents($path);

        if ($contents === false) {
            throw new LdifUrlException(sprintf('The file "%s" could not be read', $path));
        }

        return $contents;
    }
}
