<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Search\Result;

use ArrayIterator;
use Countable;
use FreeDSx\Ldap\Exception\UnexpectedValueException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use IteratorAggregate;
use Stringable;
use Traversable;
use function count;
use function implode;

/**
 * @template T of LdapUrl[]
 */
final class ReferralResult implements Countable, IteratorAggregate, Stringable
{
    /**
     * @var null|LdapUrl[]
     */
    private ?array $referrals = null;

    public function __construct(private readonly LdapMessageResponse $response)
    {}

    /**
     * The raw message response returned from the server, which contains any controls
     */
    public function getMessage(): LdapMessageResponse
    {
        return $this->response;
    }

    /**
     * Get the referrals returned for this result reference.
     *
     * @return LdapUrl[]
     */
    public function getReferrals(): array
    {
        if ($this->referrals !== null) {
            return $this->referrals;
        }
        $reference = $this->response->getResponse();

        if (!$reference instanceof SearchResultReference) {
            throw new UnexpectedValueException(sprintf(
                'Expected an instance of "%s", but got "%s".',
                SearchResultReference::class,
                get_class($reference)
            ));
        }

        $this->referrals = $reference->getReferrals();

        return $this->referrals;
    }

    /**
     * {@inheritDoc}
     *
     * The number of referrals present in the reference result.
     */
    public function count(): int
    {
        return count($this->getReferrals());
    }

    /**
     * {@inheritDoc}
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->getReferrals());
    }

    /**
     * {@inheritDoc}
     */
    public function __toString(): string
    {
        return implode(
            separator: ',',
            array: $this->getReferrals(),
        );
    }
}
