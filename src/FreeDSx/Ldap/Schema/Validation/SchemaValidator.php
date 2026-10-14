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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Exception\SchemaValidationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\Check\SchemaCheckInterface;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;

use function array_push;
use function sprintf;

/**
 * Holds the entry a write leaves behind to the schema.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SchemaValidator
{
    /**
     * What an attribute may hold when its type declares no cap of its own.
     *
     * Enough for any reasonable entry, and well below the size at which a single entry becomes expensive to read and write.
     */
    public const DEFAULT_MAX_VALUES = 10000;

    /**
     * @param list<SchemaCheckInterface> $checks Run in this order, so the first violation decides a write's result code.
     */
    public function __construct(
        private Schema $schema,
        private SchemaValidationMode $mode,
        private AttributeSyntaxResolver $syntaxResolver,
        private array $checks,
    ) {}

    public function mode(): SchemaValidationMode
    {
        return $this->mode;
    }

    /**
     * Runs every check, so a violation a caller may waive cannot hide one it may not.
     *
     * @throws SchemaValidationException
     */
    public function validate(SchemaWrite $write): void
    {
        if ($this->mode === SchemaValidationMode::Off) {
            return;
        }

        $classes = ObjectClassChain::forEntry(
            $this->schema,
            $write->entry,
        );
        $violations = [];

        foreach ($this->checks as $check) {
            array_push(
                $violations,
                ...$check->check(
                    $write,
                    $classes,
                ),
            );
        }

        if ($violations === []) {
            return;
        }

        throw new SchemaValidationException($violations);
    }

    /**
     * Holds an attribute's values to its type's syntax.
     *
     * @throws SchemaValidationException when a value does not conform
     */
    public function validateValues(Attribute $attribute): void
    {
        if ($this->mode === SchemaValidationMode::Off || $this->syntaxResolver->allConform($attribute)) {
            return;
        }

        throw new SchemaValidationException([
            new RuleViolation(
                SchemaRule::AttributeSyntax,
                ResultCode::INVALID_ATTRIBUTE_SYNTAX,
                sprintf(
                    'A value for attribute "%s" does not conform to its syntax.',
                    $attribute->getName(),
                ),
            ),
        ]);
    }
}
