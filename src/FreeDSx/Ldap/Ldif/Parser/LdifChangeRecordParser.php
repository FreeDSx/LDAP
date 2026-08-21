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

namespace FreeDSx\Ldap\Ldif\Parser;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\LdifParseException;
use FreeDSx\Ldap\Ldif\LdifChangeRecord;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operations;

use function preg_split;
use function sprintf;
use function strpos;
use function strtolower;
use function substr;
use function trim;

/**
 * Parses one RFC 2849 LDIF change record into a write request, given a cursor positioned after the dn directive.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class LdifChangeRecordParser
{
    use AttributeGroupingTrait;

    private const DN = 'dn';

    private const CONTROL = 'control';

    private const CHANGETYPE = 'changetype';

    private const MOD_TERMINATOR = '-';

    /**
     * @throws LdifParseException
     */
    public function parseRecord(
        LdifLineCursor $cursor,
        string $dn,
    ): LdifChangeRecord {
        $controls = $this->readControls($cursor);
        $changetype = $this->readChangetype($cursor);
        $type = ChangeType::tryFrom(strtolower($changetype));

        $request = match ($type) {
            ChangeType::Add => $this->parseAddRecord($cursor, $dn),
            ChangeType::Delete => $this->parseDeleteRecord($cursor, $dn),
            ChangeType::Modify => $this->parseModifyRecord($cursor, $dn),
            ChangeType::ModRdn, ChangeType::ModDn => $this->parseModRdnRecord($cursor, $dn),
            null => $cursor->error(sprintf(
                'Unsupported changetype "%s"',
                $changetype,
            )),
        };

        return new LdifChangeRecord(
            $request,
            ...$controls,
        );
    }

    /**
     * RFC 2849 places any controls between the DN and the changetype.
     *
     * @return list<Control>
     * @throws LdifParseException
     */
    private function readControls(LdifLineCursor $cursor): array
    {
        $controls = [];

        while (!$cursor->atEnd()) {
            if ($cursor->isComment($cursor->current())) {
                $cursor->skipComment();

                continue;
            }
            if ($cursor->keyOf($cursor->current()) !== self::CONTROL) {
                break;
            }

            $controls[] = $this->parseControl(
                $cursor,
                $cursor->readDirective(),
            );
        }

        return $controls;
    }

    /**
     * The body is "oid [criticality] [value-spec]", the value-spec keeping its own base64 or URL marker.
     *
     * @throws LdifParseException
     */
    private function parseControl(
        LdifLineCursor $cursor,
        LdifDirective $directive,
    ): Control {
        $separator = strpos($directive->value, ':');
        $head = $separator === false
            ? $directive->value
            : substr($directive->value, 0, $separator);
        $value = $separator === false
            ? null
            : $cursor->decodeEmbeddedValue(
                substr($directive->value, $separator + 1),
                $directive,
            );

        $parts = preg_split('/\s+/', trim($head), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $oid = $parts[0] ?? '';

        if ($oid === '') {
            $cursor->errorFor(
                $directive,
                'A "control:" directive needs a control OID',
            );
        }

        return new Control(
            $oid,
            $this->readCriticality($cursor, $directive, $parts[1] ?? null),
            $value,
        );
    }

    /**
     * @throws LdifParseException
     */
    private function readCriticality(
        LdifLineCursor $cursor,
        LdifDirective $directive,
        ?string $token,
    ): bool {
        // RFC 5234 2.3 makes the quoted literals the grammar spells "true" and "false" case insensitive.
        return match ($token === null ? 'false' : strtolower($token)) {
            'false' => false,
            'true' => true,
            default => $cursor->errorFor(
                $directive,
                sprintf('A control criticality must be "true" or "false", got "%s"', $token),
            ),
        };
    }

    /**
     * @throws LdifParseException
     */
    private function readChangetype(LdifLineCursor $cursor): string
    {
        while (!$cursor->atEnd() && $cursor->isComment($cursor->current())) {
            $cursor->skipComment();
        }

        if ($cursor->atEnd() || $cursor->current() === '') {
            $cursor->error('Missing "changetype:" directive after DN');
        }

        $directive = $cursor->readDirective();

        if (!$directive->is(self::CHANGETYPE)) {
            $cursor->errorFor(
                $directive,
                'Expected "changetype:" directive after DN',
            );
        }

        return $directive->value;
    }

    /**
     * @throws LdifParseException
     */
    private function parseAddRecord(
        LdifLineCursor $cursor,
        string $dn,
    ): AddRequest {
        $attributes = $this->readAttrvalBody($cursor);

        return Operations::add(Entry::create(
            $dn,
            $attributes,
        ));
    }

    /**
     * @throws LdifParseException
     */
    private function parseDeleteRecord(
        LdifLineCursor $cursor,
        string $dn,
    ): DeleteRequest {
        $this->expectEndOfRecord(
            $cursor,
            ChangeType::Delete->value,
        );

        return Operations::delete($dn);
    }

    /**
     * @throws LdifParseException
     */
    private function parseModifyRecord(
        LdifLineCursor $cursor,
        string $dn,
    ): ModifyRequest {
        $changes = [];

        while (($directive = $this->advanceToNextDirective($cursor)) !== null) {
            $changes[] = $this->parseModSpec($cursor, $directive);
        }

        return Operations::modify(
            $dn,
            ...$changes,
        );
    }

    /**
     * @throws LdifParseException
     */
    private function parseModSpec(
        LdifLineCursor $cursor,
        LdifDirective $directive,
    ): Change {
        $op = ModSpecOp::tryFrom(strtolower($directive->name));
        $attr = $directive->value;

        if ($op === null) {
            $cursor->errorFor(
                $directive,
                sprintf(
                    'Expected an add:, delete:, or replace: mod-spec, got "%s:"',
                    $directive->name,
                ),
            );
        }

        $values = $this->readModSpecValues(
            $cursor,
            $attr,
        );

        return match ($op) {
            ModSpecOp::Add => Change::add($attr, ...$values),
            ModSpecOp::Delete => Change::delete($attr, ...$values),
            ModSpecOp::Replace => Change::replace($attr, ...$values),
        };
    }

    /**
     * @return list<string>
     * @throws LdifParseException
     */
    private function readModSpecValues(
        LdifLineCursor $cursor,
        string $attr,
    ): array {
        $values = [];

        while (!$cursor->atEnd()) {
            $line = $cursor->current();

            if ($line === self::MOD_TERMINATOR) {
                $cursor->advance();

                return $values;
            }
            if ($cursor->isComment($line)) {
                $cursor->skipComment();
                continue;
            }
            if ($line === '' || $cursor->keyOf($line) === self::DN) {
                break;
            }

            $directive = $cursor->readDirective();

            if (!$directive->is($attr)) {
                $cursor->errorFor(
                    $directive,
                    sprintf(
                        'Mod-spec attribute "%s" does not match values for "%s"',
                        $directive->name,
                        $attr,
                    ),
                );
            }

            $values[] = $directive->value;
        }

        $cursor->error(sprintf(
            'Mod-spec for "%s" missing "-" terminator',
            $attr,
        ));
    }

    /**
     * @throws LdifParseException
     */
    private function parseModRdnRecord(
        LdifLineCursor $cursor,
        string $dn,
    ): ModifyDnRequest {
        $newRdn = null;
        $deleteOldRdn = null;
        $newSuperior = null;

        while (($directive = $this->advanceToNextDirective($cursor)) !== null) {
            $field = ModRdnDirective::tryFrom(strtolower($directive->name));

            match ($field) {
                ModRdnDirective::NewRdn => $newRdn = $this->assignFieldOnce(
                    $newRdn,
                    $directive,
                    $cursor,
                ),
                ModRdnDirective::DeleteOldRdn => $deleteOldRdn = $this->assignDeleteOldRdnOnce(
                    $deleteOldRdn,
                    $directive,
                    $cursor,
                ),
                ModRdnDirective::NewSuperior => $newSuperior = $this->assignFieldOnce(
                    $newSuperior,
                    $directive,
                    $cursor,
                ),
                null => $cursor->errorFor(
                    $directive,
                    sprintf(
                        'Unexpected directive "%s:" in modrdn record',
                        $directive->name,
                    ),
                ),
            };
        }

        if ($newRdn === null) {
            $cursor->error('Missing "newrdn:" in modrdn record');
        }
        if ($deleteOldRdn === null) {
            $cursor->error('Missing "deleteoldrdn:" in modrdn record');
        }

        return new ModifyDnRequest(
            $dn,
            $newRdn,
            $deleteOldRdn,
            $newSuperior,
        );
    }

    /**
     * @throws LdifParseException
     */
    private function assignFieldOnce(
        ?string $current,
        LdifDirective $directive,
        LdifLineCursor $cursor,
    ): string {
        if ($current !== null) {
            $cursor->errorFor(
                $directive,
                sprintf(
                    'Duplicate "%s:" in modrdn record',
                    strtolower($directive->name),
                ),
            );
        }

        return $directive->value;
    }

    /**
     * @throws LdifParseException
     */
    private function assignDeleteOldRdnOnce(
        ?bool $current,
        LdifDirective $directive,
        LdifLineCursor $cursor,
    ): bool {
        if ($current !== null) {
            $cursor->errorFor(
                $directive,
                'Duplicate "deleteoldrdn:" in modrdn record',
            );
        }
        if ($directive->value === '0') {
            return false;
        }
        if ($directive->value === '1') {
            return true;
        }

        $cursor->errorFor(
            $directive,
            sprintf(
                '"deleteoldrdn" must be 0 or 1, got "%s"',
                $directive->value,
            ),
        );
    }

    /**
     * @return array<string, string[]>
     * @throws LdifParseException
     */
    private function readAttrvalBody(LdifLineCursor $cursor): array
    {
        $directives = [];

        while (($directive = $this->advanceToNextDirective($cursor)) !== null) {
            $directives[] = $directive;
        }

        return $this->groupAttributeValues($directives);
    }

    /**
     * @throws LdifParseException
     */
    private function expectEndOfRecord(
        LdifLineCursor $cursor,
        string $changetype,
    ): void {
        while (!$cursor->atEnd()) {
            $line = $cursor->current();

            if ($line === '') {
                return;
            }
            if ($cursor->isComment($line)) {
                $cursor->skipComment();
                continue;
            }
            if ($cursor->keyOf($line) === self::DN) {
                return;
            }

            $cursor->error(sprintf(
                'Unexpected directive after "changetype: %s"',
                $changetype,
            ));
        }
    }

    /**
     * Skips comments and returns the next directive, or null at end-of-record (blank line, dn:, or EOF).
     *
     * @throws LdifParseException
     */
    private function advanceToNextDirective(LdifLineCursor $cursor): ?LdifDirective
    {
        while (!$cursor->atEnd()) {
            $line = $cursor->current();

            if ($line === '') {
                return null;
            }
            if ($cursor->isComment($line)) {
                $cursor->skipComment();
                continue;
            }
            if ($cursor->keyOf($line) === self::DN) {
                return null;
            }

            return $cursor->readDirective();
        }

        return null;
    }
}
