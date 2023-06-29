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

namespace FreeDSx\Ldap\Operation\Request;

use Closure;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;

class SyncRequest extends SearchRequest
{
    private ?Closure $syncIdSetHandler = null;

    private ?Closure $cookieHandler = null;

    public function __construct(
        ?FilterInterface $filter = null,
        string|Attribute ...$attributes
    ) {
        parent::__construct(
            $filter ?? Filters::present('objectClass'),
            ...$attributes,
        );
    }

    public function useIdSetHandler(?Closure $syncIdSetHandler): self
    {
        $this->syncIdSetHandler = $syncIdSetHandler;

        return $this;
    }

    public function getIdSetHandler(): ?Closure
    {
        return $this->syncIdSetHandler;
    }

    public function useCookieHandler(?Closure $cookieUpdateHandler): self
    {
        $this->cookieHandler = $cookieUpdateHandler;

        return $this;
    }

    public function getCookieHandler(): ?Closure
    {
        return $this->cookieHandler;
    }
}
