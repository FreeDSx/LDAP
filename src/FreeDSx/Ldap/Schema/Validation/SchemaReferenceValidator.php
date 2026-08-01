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

namespace FreeDSx\Ldap\Schema\Validation;

use FreeDSx\Ldap\Exception\SchemaParseException;
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\DefinitionKeyword;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaLoadMode;

use function sprintf;

/**
 * Checks that parsed definitions only reference definitions that exist, in the parsed schema or the base one.
 *
 * Matching rule references are not checked; an unknown rule falls back to default comparison semantics rather
 * than failing, so the definition remains usable.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SchemaReferenceValidator
{
    /**
     * @param Schema $base an additional schema the definitions may resolve against, beyond their own; pass an empty
     *                     schema when what is being checked is already complete
     */
    public function __construct(private Schema $base) {}

    /**
     * @throws SchemaParseException
     */
    public function validate(
        Schema $parsed,
        SchemaLoadMode $mode,
    ): void {
        if ($mode === SchemaLoadMode::Lenient) {
            return;
        }

        foreach ($parsed->getAttributeTypes() as $type) {
            $this->checkAttributeType(
                $parsed,
                $type,
            );
        }

        foreach ($parsed->getObjectClasses() as $class) {
            $this->checkObjectClass(
                $parsed,
                $class,
            );
        }
    }

    /**
     * @throws SchemaParseException
     */
    private function checkAttributeType(
        Schema $parsed,
        AttributeType $type,
    ): void {
        $label = $type->names[0] ?? $type->oid;
        $superTypeOid = $type->superTypeOid;
        $syntaxOid = $type->syntaxOid;

        if ($superTypeOid !== null && !$this->knowsAttributeType($parsed, $superTypeOid)) {
            $this->fail(
                $label,
                DefinitionKeyword::SUP,
                $superTypeOid,
            );
        }

        if ($syntaxOid !== null && !$this->knowsSyntax($parsed, $syntaxOid)) {
            $this->fail(
                $label,
                DefinitionKeyword::SYNTAX,
                $syntaxOid,
            );
        }
    }

    /**
     * @throws SchemaParseException
     */
    private function checkObjectClass(
        Schema $parsed,
        ObjectClass $class,
    ): void {
        $label = $class->names[0] ?? $class->oid;

        $this->assertResolvable(
            $class->superClassOids,
            fn(string $oid): bool => $this->knowsObjectClass($parsed, $oid),
            $label,
            DefinitionKeyword::SUP,
        );
        $this->assertResolvable(
            $class->must,
            fn(string $oid): bool => $this->knowsAttributeType($parsed, $oid),
            $label,
            DefinitionKeyword::MUST,
        );
        $this->assertResolvable(
            $class->may,
            fn(string $oid): bool => $this->knowsAttributeType($parsed, $oid),
            $label,
            DefinitionKeyword::MAY,
        );
    }

    /**
     * @param list<string> $oids
     * @param callable(string): bool $isKnown
     * @throws SchemaParseException
     */
    private function assertResolvable(
        array $oids,
        callable $isKnown,
        string $label,
        string $keyword,
    ): void {
        foreach ($oids as $oid) {
            if (!$isKnown($oid)) {
                $this->fail(
                    $label,
                    $keyword,
                    $oid,
                );
            }
        }
    }

    private function knowsAttributeType(
        Schema $parsed,
        string $nameOrOid,
    ): bool {
        return $parsed->getAttributeType($nameOrOid) !== null
            || $this->base->getAttributeType($nameOrOid) !== null;
    }

    private function knowsObjectClass(
        Schema $parsed,
        string $nameOrOid,
    ): bool {
        return $parsed->getObjectClass($nameOrOid) !== null
            || $this->base->getObjectClass($nameOrOid) !== null;
    }

    private function knowsSyntax(
        Schema $parsed,
        string $oid,
    ): bool {
        return $parsed->getSyntax($oid) !== null
            || $this->base->getSyntax($oid) !== null;
    }

    /**
     * @throws SchemaParseException
     */
    private function fail(
        string $label,
        string $keyword,
        string $oid,
    ): never {
        throw new SchemaParseException(sprintf(
            'The definition for "%s" references an unknown %s "%s".',
            $label,
            $keyword,
            $oid,
        ));
    }
}
