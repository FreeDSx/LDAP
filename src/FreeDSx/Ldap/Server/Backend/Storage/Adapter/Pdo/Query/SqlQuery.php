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

/**
 * Immutable SQL + bound parameters pair.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SqlQuery
{
    /**
     * @param list<string|int> $params
     */
    public function __construct(
        public string $sql,
        public array $params = [],
    ) {}

    /**
     * Returns a new instance with the given SQL appended and params merged.
     *
     * @param list<string|int> $additionalParams
     */
    public function appending(
        string $sql,
        array $additionalParams = [],
    ): self {
        return new self(
            $this->sql . $sql,
            array_merge(
                $this->params,
                $additionalParams,
            ),
        );
    }
}
