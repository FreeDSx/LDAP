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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler\Admission;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AttributeProjection;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\Read\ReadScopeInterface;
use FreeDSx\Ldap\Server\AccessControl\Read\ReadVerdict;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\StrippedEntryMatcher;
use FreeDSx\Ldap\Server\Token\TokenInterface;

use function count;

/**
 * Decides in one pass what a search request returns of each entry it matched, remembering per attribute description.
 *
 * @internal
 */
final class SearchResultGate
{
    /**
     * Stored descriptions are arbitrary, and only these many decisions are remembered.
     */
    private const MAX_REMEMBERED_DESCRIPTIONS = 1024;

    /**
     * @var array<string, AttributeAdmission|bool> A bool when the description is returned or dropped on every entry.
     */
    private array $admissions = [];

    /**
     * Decisions are only kept from the second entry, since a request returning one gains nothing from them.
     */
    private bool $remembering = false;

    private ReadScopeInterface $scope;

    /**
     * @var array<string, ReadVerdict> The linked types the filter names that are not readable on every entry.
     */
    private array $linkedReads;

    private function __construct(
        private readonly AccessControlInterface $accessControl,
        private readonly StrippedEntryMatcher $strippedMatcher,
        private readonly AttributeProjection $projection,
        private readonly TokenInterface $token,
        private readonly FilterInterface $filter,
    ) {
        $this->scope = $this->accessControl->readScope($this->token);
        $this->linkedReads = $this->linkedReadsOf($this->scope);
    }

    public static function forRequest(
        AccessControlInterface $accessControl,
        StrippedEntryMatcher $strippedMatcher,
        AttributeProjection $projection,
        TokenInterface $token,
        FilterInterface $filter,
    ): self {
        return new self(
            $accessControl,
            $strippedMatcher,
            $projection,
            $token,
            $filter,
        );
    }

    /**
     * The entry as the request returns it, or null when the identity may not see it or it stops matching once stripped.
     */
    public function admit(Entry $entry): ?Entry
    {
        $this->followReload();

        if (!$this->scope->isEntryVisible($entry)) {
            return null;
        }

        $dn = $entry->getDn();
        $all = $entry->getAttributes();
        $returned = [];
        $withheld = [];

        // Kept inline for performance reasons.
        foreach ($all as $attribute) {
            $admission = $this->admissions[$attribute->getDescription()] ?? $this->admissionFor($attribute);

            if ($admission === true) {
                $returned[] = $attribute;

                continue;
            }

            if ($admission === false) {
                continue;
            }

            $readable = match ($admission->read) {
                ReadVerdict::Allow => true,
                ReadVerdict::Deny => false,
                ReadVerdict::PerEntry => $this->scope->isReadableOn(
                    $admission->name,
                    $dn,
                ),
            };

            if ($readable && $admission->returned) {
                $returned[] = $attribute;
            } elseif (!$readable && $admission->concernsFilter) {
                $withheld[$admission->name] = true;
            }
        }
        $this->remembering = true;

        // The filter matches on the linked types it names whether or not the entry carries them.
        foreach ($this->linkedReads as $type => $read) {
            if ($read === ReadVerdict::Deny || !$this->scope->isReadableOn($type, $dn)) {
                $withheld[$type] = true;
            }
        }

        if ($withheld !== [] && !$this->strippedMatcher->stillMatches($entry, $withheld, $this->filter)) {
            return null;
        }

        return $this->projection->withAttributes(
            $entry,
            $returned,
            count($returned) === count($all),
        );
    }

    /**
     * A reload replaces the policy for the entries still to come, as it does for every other decision.
     */
    private function followReload(): void
    {
        if ($this->scope->isCurrent()) {
            return;
        }

        $this->scope = $this->accessControl->readScope($this->token);
        $this->linkedReads = $this->linkedReadsOf($this->scope);
        $this->admissions = [];
    }

    /**
     * @return array<string, ReadVerdict>
     */
    private function linkedReadsOf(ReadScopeInterface $scope): array
    {
        $reads = [];

        foreach ($this->strippedMatcher->linkedTypes($this->filter) as $type) {
            $read = $scope->verdict($type);

            if ($read !== ReadVerdict::Allow) {
                $reads[$type] = $read;
            }
        }

        return $reads;
    }

    /**
     * The decision for a description not yet remembered, settled to a bool when it is the same on every entry.
     */
    private function admissionFor(Attribute $attribute): AttributeAdmission|bool
    {
        $description = $attribute->getDescription();
        $decided = $this->decideAdmission($attribute);
        $admission = $decided->returnedOnEveryEntry() ?? $decided;

        if ($this->remembering && count($this->admissions) < self::MAX_REMEMBERED_DESCRIPTIONS) {
            $this->admissions[$description] = $admission;
        }

        return $admission;
    }

    /**
     * An attribute neither returned nor read by the filter is dropped without a read decision ever being made.
     */
    private function decideAdmission(Attribute $attribute): AttributeAdmission
    {
        $name = Attribute::normalizeName($attribute->getName());
        $returned = $this->projection->includes($attribute);

        if (!$returned && !$this->strippedMatcher->concerns($this->filter, $name)) {
            return new AttributeAdmission(
                $name,
                false,
                ReadVerdict::Deny,
                false,
            );
        }
        $read = $this->scope->verdict($name);

        return new AttributeAdmission(
            $name,
            $returned,
            $read,
            $read !== ReadVerdict::Allow && $this->strippedMatcher->concerns(
                $this->filter,
                $name,
            ),
        );
    }
}
