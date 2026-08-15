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

namespace FreeDSx\Ldap\Sync\Provider;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Sync\Provider\Exception\MalformedSyncCookieException;
use JsonException;

/**
 * Opaque, versioned RFC 4533 sync cookie carrying the origin replica and its seq high-water mark.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SyncCookie
{
    /**
     * Encoding version; bumped if the blob grows (e.g. a per-origin vector for multi-master).
     */
    private const VERSION = 2;

    public function __construct(
        public ReplicaId $origin,
        public int $seq,
        public string $content = '',
    ) {
        if ($this->seq < 0) {
            throw new InvalidArgumentException('A sync cookie seq cannot be negative.');
        }
    }

    /**
     * Identifies the content a cookie was issued for, so it cannot be replayed against a different search.
     *
     * RFC 4533 §3.5 makes every search request field content-controlling except the two limits, which bound an
     * operation rather than describing the content.
     */
    public static function contentKey(SearchRequest $request): string
    {
        $attributes = array_map(
            static fn(Attribute $attribute): string => strtolower($attribute->getDescription()),
            $request->getAttributes(),
        );
        sort($attributes);

        return hash('sha256', implode("\0", [
            (string) $request->getBaseDn(),
            (string) $request->getScope(),
            (string) $request->getDereferenceAliases(),
            $request->getAttributesOnly() ? '1' : '0',
            $request->getFilter()->toString(),
            implode(',', $attributes),
        ]));
    }

    public function encode(): string
    {
        return base64_encode(json_encode(
            [
                'v' => self::VERSION,
                'origin' => (string) $this->origin,
                'seq' => $this->seq,
                'content' => $this->content,
            ],
            JSON_THROW_ON_ERROR,
        ));
    }

    /**
     * @throws MalformedSyncCookieException
     */
    public static function decode(string $cookie): self
    {
        $json = base64_decode($cookie, true);

        if ($json === false) {
            throw new MalformedSyncCookieException('The sync cookie is not valid base64.');
        }

        try {
            $data = json_decode(
                $json,
                true,
                flags: JSON_THROW_ON_ERROR,
            );
        } catch (JsonException $e) {
            throw new MalformedSyncCookieException(
                'The sync cookie is not valid JSON.',
                previous: $e,
            );
        }

        if (!is_array($data) || ($data['v'] ?? null) !== self::VERSION) {
            throw new MalformedSyncCookieException('The sync cookie has an unsupported version.');
        }

        $origin = $data['origin'] ?? null;
        $seq = $data['seq'] ?? null;
        $content = $data['content'] ?? null;

        if (!is_string($origin) || $origin === '' || !is_int($seq) || $seq < 0) {
            throw new MalformedSyncCookieException('The sync cookie is missing a valid origin or seq.');
        }

        if (!is_string($content)) {
            throw new MalformedSyncCookieException('The sync cookie is missing its content key.');
        }

        return new self(
            new ReplicaId($origin),
            $seq,
            $content,
        );
    }
}
