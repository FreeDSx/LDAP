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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SortKeySpec;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Backend\Storage\Search\Options\ListScope;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * The SQL-side view of a list request: its scope, the translated filter, and the rows to read.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ListQuerySpec
{
    /**
     * @param list<SortKeySpec> $sortKeys
     * @param ?int $limit Rows the query may return, or null for no bound.
     */
    public function __construct(
        public ListScope $scope,
        public ?SqlFilterResult $filter,
        public ?int $limit,
        public array $sortKeys = [],
        public ?PageCursor $after = null,
        public bool $withChildFlag = false,
    ) {}

    /**
     * @param list<SortKeySpec> $sortKeys
     */
    public static function fromOptions(
        StorageListOptions $options,
        ?SqlFilterResult $filter,
        ?int $limit,
        array $sortKeys,
    ): self {
        return new self(
            scope: $options->scope,
            filter: $filter,
            limit: $limit,
            sortKeys: $sortKeys,
            after: $options->bounds->resumeAfter(),
            withChildFlag: $options->projection->withHasSubordinates,
        );
    }

    /**
     * The normalized base DN the query scopes on.
     */
    public function base(): string
    {
        return $this->scope->baseDn->normalizedString();
    }

    /**
     * The same spec seeking past $after, for the next batch of a walk.
     */
    public function resumingAfter(PageCursor $after): self
    {
        return new self(
            scope: $this->scope,
            filter: $this->filter,
            limit: $this->limit,
            sortKeys: $this->sortKeys,
            after: $after,
            withChildFlag: $this->withChildFlag,
        );
    }
}
