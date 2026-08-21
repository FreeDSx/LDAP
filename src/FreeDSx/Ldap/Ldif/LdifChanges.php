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

namespace FreeDSx\Ldap\Ldif;

use ArrayIterator;
use Countable;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Ldif\Loader\LdifLoaderInterface;
use FreeDSx\Ldap\Ldif\Loader\StringLdifLoader;
use FreeDSx\Ldap\Ldif\Url\LdifUrlResolverInterface;
use FreeDSx\Ldap\Ldif\Url\RefusingUrlResolver;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use IteratorAggregate;
use Traversable;

use function array_filter;
use function array_map;
use function array_values;
use function count;

/**
 * The full outcome of an LDIF parse: records in original order, each a request with any controls it carried.
 *
 * @api
 *
 * @implements IteratorAggregate<LdifChangeRecord>
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LdifChanges implements Countable, IteratorAggregate
{
    /**
     * @var list<LdifChangeRecord>
     */
    private array $records;

    public function __construct(LdifChangeRecord ...$records)
    {
        $this->records = array_values($records);
    }

    /**
     * Buffers a loader's parsed records into a collection. For streaming, iterate {@see LdifParser::parse()} directly.
     */
    public static function fromLoader(
        LdifLoaderInterface $loader,
        LdifParser $parser = new LdifParser(),
        LdifUrlResolverInterface $urlResolver = new RefusingUrlResolver(),
    ): self {
        return new self(...$parser->parse(
            $loader,
            $urlResolver,
        ));
    }

    /**
     * Convenience for buffering an in-memory LDIF string via {@see StringLdifLoader}.
     */
    public static function fromString(
        string $ldif,
        LdifParser $parser = new LdifParser(),
        LdifUrlResolverInterface $urlResolver = new RefusingUrlResolver(),
    ): self {
        return self::fromLoader(
            new StringLdifLoader($ldif),
            $parser,
            $urlResolver,
        );
    }

    /**
     * @return list<LdifChangeRecord>
     */
    public function toArray(): array
    {
        return $this->records;
    }

    public function count(): int
    {
        return count($this->records);
    }

    /**
     * @return Traversable<LdifChangeRecord>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->records);
    }

    /**
     * The requests alone, for callers with no interest in the controls a record may carry.
     *
     * @return list<RequestInterface>
     */
    public function requests(): array
    {
        return array_map(
            static fn(LdifChangeRecord $record): RequestInterface => $record->request,
            $this->records,
        );
    }

    /**
     * @return list<AddRequest>
     */
    public function adds(): array
    {
        return $this->requestsOfType(AddRequest::class);
    }

    /**
     * @return list<ModifyRequest>
     */
    public function modifies(): array
    {
        return $this->requestsOfType(ModifyRequest::class);
    }

    /**
     * @return list<DeleteRequest>
     */
    public function deletes(): array
    {
        return $this->requestsOfType(DeleteRequest::class);
    }

    /**
     * @return list<ModifyDnRequest>
     */
    public function modifyDns(): array
    {
        return $this->requestsOfType(ModifyDnRequest::class);
    }

    public function isAddOnly(): bool
    {
        foreach ($this->records as $record) {
            if (!($record->request instanceof AddRequest)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Extracts the Entry from every AddRequest, ignoring any non-add requests.
     *
     * @return list<Entry>
     */
    public function entries(): array
    {
        return array_map(
            fn(AddRequest $r): Entry => $r->getEntry(),
            $this->adds(),
        );
    }

    /**
     * @template T of RequestInterface
     * @param class-string<T> $type
     * @return list<T>
     */
    private function requestsOfType(string $type): array
    {
        return array_values(array_filter(
            $this->requests(),
            static fn(RequestInterface $request): bool => $request instanceof $type,
        ));
    }
}
