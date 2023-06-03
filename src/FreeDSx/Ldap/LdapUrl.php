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

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\UrlParseException;
use Stringable;
use function array_map;
use function count;
use function end;
use function explode;
use function implode;
use function key;
use function ltrim;
use function parse_url;
use function preg_match;
use function reset;
use function str_contains;
use function strlen;
use function strtolower;

/**
 * Represents a LDAP URL. RFC 4516.
 *
 * @see https://tools.ietf.org/html/rfc4516
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapUrl implements Stringable
{
    use LdapUrlTrait;

    public const SCOPE_BASE = 'base';

    public const SCOPE_ONE = 'one';

    public const SCOPE_SUB = 'sub';

    private ?int $port = null;

    private bool $useSsl = false;

    private ?string $host;

    private ?Dn $dn = null;

    private ?string $scope = null;

    /**
     * @var Attribute[]
     */
    private array $attributes = [];

    private ?string $filter = null;

    /**
     * @var LdapUrlExtension[]
     */
    private array $extensions = [];

    public function __construct(?string $host = null)
    {
        $this->host = $host;
    }

    public function setDn(Dn|string|null $dn): self
    {
        $this->dn = $dn === null
            ? $dn
            : new Dn((string) $dn);

        return $this;
    }

    public function getDn(): ?Dn
    {
        return $this->dn;
    }

    public function getHost(): ?string
    {
        return $this->host;
    }

    public function setHost(?string $host): self
    {
        $this->host = $host;

        return $this;
    }

    public function setPort(?int $port): self
    {
        $this->port = $port;

        return $this;
    }

    public function getPort(): ?int
    {
        return $this->port;
    }

    public function getScope(): ?string
    {
        return $this->scope;
    }

    /**
     * @throws InvalidArgumentException
     */
    public function setScope(?string $scope): self
    {
        $scope = $scope === null ? $scope : strtolower($scope);
        if ($scope !== null && !in_array($scope, [self::SCOPE_BASE, self::SCOPE_ONE, self::SCOPE_SUB], true)) {
            throw new InvalidArgumentException(sprintf(
                'The scope "%s" is not valid. It must be one of: %s, %s, %s',
                $scope,
                self::SCOPE_BASE,
                self::SCOPE_ONE,
                self::SCOPE_SUB
            ));
        }
        $this->scope = $scope;

        return $this;
    }

    public function getFilter(): ?string
    {
        return $this->filter;
    }

    public function setFilter(?string $filter): self
    {
        $this->filter = $filter;

        return $this;
    }

    /**
     * @return LdapUrlExtension[]
     */
    public function getExtensions(): array
    {
        return $this->extensions;
    }

    public function setExtensions(LdapUrlExtension ...$extensions): self
    {
        $this->extensions = $extensions;

        return $this;
    }

    /**
     * @return Attribute[]
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    public function setAttributes(Attribute|string ...$attributes): self
    {
        $attr = [];
        foreach ($attributes as $attribute) {
            $attr[] = $attribute instanceof Attribute
                ? $attribute
                : new Attribute($attribute);
        }
        $this->attributes = $attr;

        return $this;
    }

    public function setUseSsl(bool $useSsl): self
    {
        $this->useSsl = $useSsl;

        return $this;
    }

    public function getUseSsl(): bool
    {
        return $this->useSsl;
    }

    /**
     * Get the string representation of the URL.
     */
    public function toString(): string
    {
        $url = ($this->useSsl ? 'ldaps' : 'ldap') . '://' . $this->host;

        if ($this->host !== null && $this->port !== null) {
            $url .= ':' . $this->port;
        }

        return $url
            . '/'
            . ($this->dn !== null ? self::encode($this->dn->toString()) : '')
            . $this->getQueryString();
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * Given a string LDAP URL, get its object representation.
     *
     * @throws UrlParseException
     * @throws InvalidArgumentException
     */
    public static function parse(string $ldapUrl): LdapUrl
    {
        $pieces = self::explodeUrl($ldapUrl);

        $url = new LdapUrl($pieces['host'] ?? null);
        $url->setUseSsl($pieces['scheme'] === 'ldaps');
        $url->setPort(isset($pieces['port']) ? (int) $pieces['port'] : null);
        $url->setDn((isset($pieces['path']) && $pieces['path'] !== '/') ? self::decode(ltrim($pieces['path'], '/')) : null);

        $query = explode('?', $pieces['query'] ?? '');
        if (count($query) !== 0) {
            $url->setAttributes(...($query[0] === '' ? [] : explode(',', $query[0])));
            $url->setScope(isset($query[1]) && $query[1] !== '' ? $query[1] : null);
            $url->setFilter(isset($query[2]) && $query[2] !== '' ? self::decode($query[2]) : null);

            $extensions = [];
            if (isset($query[3]) && $query[3] !== '') {
                $extensions = array_map(function ($ext) {
                    return LdapUrlExtension::parse($ext);
                }, explode(',', $query[3]));
            }
            $url->setExtensions(...$extensions);
        }

        return $url;
    }

    /**
     * @return array{scheme: ?string, path: ?string, query: ?string, host: ?string, port: ?string}
     * @throws UrlParseException
     */
    private static function explodeUrl(string $url): array
    {
        $pieces = parse_url($url);

        if ($pieces === false || !isset($pieces['scheme'])) {
            # We are on our own here if it's an empty host, as parse_url will not treat it as valid, though it is valid
            # for LDAP URLs. In the case of an empty host a client should determine what host to connect to.
            if (preg_match('/^(ldaps?)\:\/\/\/(.*)$/', $url, $matches) === 0) {
                throw new UrlParseException(sprintf('The LDAP URL is malformed: %s', $url));
            }
            $query = null;
            $path = null;

            # Check for query parameters but no path...
            if (strlen($matches[2]) > 0 && $matches[2][0] === '?') {
                $query = substr($matches[2], 1);
            # Check if there are any query parameters and a possible path...
            } elseif (str_contains($matches[2], '?')) {
                $parts = explode('?', $matches[2], 2);
                $path = $parts[0];
                $query = $parts[1] ?? null;
            # A path only...
            } else {
                $path = $matches[2];
            }

            $pieces = [
                'scheme' => $matches[1],
                'path' => $path,
                'query' => $query,
            ];
        }
        $pieces['scheme'] = strtolower($pieces['scheme']);

        if (!($pieces['scheme'] === 'ldap' || $pieces['scheme'] === 'ldaps')) {
            throw new UrlParseException(sprintf(
                'The URL scheme "%s" is not valid. It must be "ldap" or "ldaps".',
                $pieces['scheme']
            ));
        }

        /** @phpstan-ignore-next-line */
        return $pieces;
    }

    /**
     * Generate the query part of the URL string representation. Only generates the parts actually used.
     */
    private function getQueryString(): string
    {
        $query = [];

        if (count($this->attributes) !== 0) {
            $query[0] = implode(',', array_map(function (Attribute $v) {
                return self::encode($v->getDescription());
            }, $this->attributes));
        }
        if ($this->scope !== null) {
            $query[1] = self::encode($this->scope);
        }
        if ($this->filter !== null) {
            $query[2] = self::encode($this->filter);
        }
        if (count($this->extensions) !== 0) {
            $query[3] = implode(',', $this->extensions);
        }

        if (count($query) === 0) {
            return '';
        }

        end($query);
        $last = key($query);
        reset($query);

        # This is so we stop at the last query part that was actually set, but also capture cases where the first and
        # third were set but not the second.
        $url = '';
        for ($i = 0; $i <= $last; $i++) {
            $url .= '?';
            if (isset($query[$i])) {
                $url .= $query[$i];
            }
        }

        return $url;
    }
}
