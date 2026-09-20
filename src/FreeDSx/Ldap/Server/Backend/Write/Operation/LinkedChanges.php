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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\LinkedValueLookupInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

use function array_diff;
use function array_filter;
use function array_values;
use function sprintf;

/**
 * Separates the linked values a modify changes from the changes its entry is still stored whole for.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LinkedChanges
{
    public function __construct(
        private LinkedAttributes $linked,
        private LinkedValueLookupInterface $lookup,
        private SchemaValidator $schema,
    ) {}

    /**
     * Holds the delta to what the owner links, which the entry is no longer carrying for the validator to see.
     *
     * @throws OperationException when a value is already linked, is not linked, or is not a DN
     */
    public function assertApplicable(
        LinkDelta $delta,
        Dn $owner,
    ): void {
        foreach ($delta->names() as $name) {
            $added = $delta->added($name);
            $removed = $delta->removed($name);

            $this->assertDistinctDns($name, $added);
            $this->assertDistinctDns($name, $removed);

            $this->refuse(
                $name,
                $this->lookup->heldLinkValues($owner, $name, $added),
                'already holds',
                ResultCode::ATTRIBUTE_OR_VALUE_EXISTS,
            );
            $this->refuse(
                $name,
                array_values(array_diff(
                    $removed,
                    $this->lookup->heldLinkValues($owner, $name, $removed),
                )),
                'does not hold',
                ResultCode::NO_SUCH_ATTRIBUTE,
            );
        }
    }

    /**
     * The values the modify links and unlinks or nothing when it has to be applied to the whole entry.
     */
    public function delta(
        UpdateCommand $command,
        WriteContext $context,
    ): LinkDelta {
        // A control reading the entry needs every value it holds, which only the whole-entry path materializes.
        if ($this->linked->isEmpty() || $context->controlEvaluator()?->inspectsEntry() === true) {
            return new LinkDelta();
        }
        $added = [];
        $removed = [];

        foreach ($command->changes as $change) {
            if (!$this->linked->links($change->getAttribute())) {
                continue;
            }

            // One change the attribute has to be written whole for settles it for every value of that attribute.
            if (!$this->isApplicable($change, $command->dn)) {
                return new LinkDelta();
            }
            $name = Attribute::normalizeName($change->getAttribute()->getName());
            $values = array_values($change->getAttribute()->getValues());

            if ($change->isAdd()) {
                $added[$name] = [...$added[$name] ?? [], ...$values];

                continue;
            }

            $removed[$name] = [...$removed[$name] ?? [], ...$values];
        }

        return new LinkDelta($added, $removed);
    }

    /**
     * The command without the changes the delta carries, which is what the entry is still stored for.
     */
    public function remaining(
        UpdateCommand $command,
        LinkDelta $delta,
    ): UpdateCommand {
        if ($delta->isEmpty()) {
            return $command;
        }

        return new UpdateCommand(
            $command->dn,
            array_values(array_filter(
                $command->changes,
                fn(Change $change): bool => !$this->linked->links($change->getAttribute()),
            )),
            $command->systemChanges,
        );
    }

    /**
     * Every value has to be a DN the attribute does not already name twice in the one request.
     *
     * @param list<string> $values
     *
     * @throws OperationException
     */
    private function assertDistinctDns(
        string $name,
        array $values,
    ): void {
        if ($values === []) {
            return;
        }

        // Held to the same syntax the whole entry would have been, which no longer carries these values.
        $this->schema->validateValues(new Attribute($name, ...$values));
        $seen = [];

        foreach ($values as $value) {
            $normalized = Dn::normalizedOrNull($value) ?? $value;

            if (isset($seen[$normalized])) {
                throw new OperationException(
                    sprintf('The attribute "%s" was given the same value twice.', $name),
                    ResultCode::ATTRIBUTE_OR_VALUE_EXISTS,
                );
            }

            $seen[$normalized] = true;
        }
    }

    /**
     * @param list<string> $offending
     *
     * @throws OperationException
     */
    private function refuse(
        string $name,
        array $offending,
        string $reason,
        int $code,
    ): void {
        if ($offending === []) {
            return;
        }

        throw new OperationException(
            sprintf('The entry %s a value given for the attribute "%s".', $reason, $name),
            $code,
        );
    }

    /**
     * Whether the change names the values it changes, rather than restating what the attribute holds.
     */
    private function isApplicable(
        Change $change,
        Dn $dn,
    ): bool {
        // Naming the entry, so the attribute is held to the RDN it spells rather than changed on its own.
        if ($dn->getRdn()->has($change->getAttribute()->getName())) {
            return false;
        }

        if ($change->isAdd()) {
            return $change->getAttribute()->getValues() !== [];
        }

        // A delete naming no value empties the attribute, which takes knowing everything it holds.
        return $change->isDelete() && !$change->isReset();
    }
}
