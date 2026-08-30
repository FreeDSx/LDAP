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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Ldif\Parser\ChangeType;
use FreeDSx\Ldap\Ldif\Parser\ModSpecOp;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use LogicException;

use function array_map;
use function array_merge;
use function array_values;
use function base64_encode;
use function implode;
use function max;
use function preg_match;
use function sprintf;
use function str_split;
use function strlen;
use function substr;

/**
 * Serializes write requests to RFC 2849 LDIF (content and change records).
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LdifWriter
{
    public function __construct(private LdifOutputOptions $options = new LdifOutputOptions()) {}

    /**
     * @param iterable<RequestInterface> $requests
     * @throws InvalidArgumentException when a request type is not serializable to LDIF
     */
    public function write(iterable $requests): string
    {
        $blocks = [];

        foreach ($requests as $request) {
            $blocks[] = $this->writeOne($request);
        }

        return $this->versionHeader() . implode($this->options->getLineEnding(), $blocks);
    }

    /**
     * The blank line RFC 2849 requires between records.
     */
    public function recordSeparator(): string
    {
        return $this->options->getLineEnding();
    }

    /**
     * Returns the LDIF "version: 1" header (with trailing blank line) when enabled, otherwise empty.
     */
    public function versionHeader(): string
    {
        return $this->options->isIncludeVersion()
            ? 'version: 1' . $this->options->getLineEnding() . $this->options->getLineEnding()
            : '';
    }

    /**
     * Serializes a single request to its LDIF block (ending with the configured line ending).
     *
     * @throws InvalidArgumentException
     */
    public function writeOne(RequestInterface $request): string
    {
        return match (true) {
            $request instanceof AddRequest => $this->addBlock($request),
            $request instanceof DeleteRequest => $this->deleteBlock($request),
            $request instanceof ModifyRequest => $this->modifyBlock($request),
            $request instanceof ModifyDnRequest => $this->modRdnBlock($request),
            default => throw new InvalidArgumentException(sprintf(
                'Unsupported request type for LDIF output: %s',
                $request::class,
            )),
        };
    }

    private function addBlock(AddRequest $request): string
    {
        $entry = $request->getEntry();
        $prelude = [$this->line('dn', $entry->getDn()->toString())];

        if ($this->options->isEmitChangetypeForAdds()) {
            $prelude[] = $this->line(
                'changetype',
                ChangeType::Add->value,
            );
        }

        $lines = array_merge(
            $prelude,
            ...array_map(
                $this->attributeLines(...),
                $entry->getAttributes(),
            ),
        );

        return implode($this->options->getLineEnding(), $lines) . $this->options->getLineEnding();
    }

    private function deleteBlock(DeleteRequest $request): string
    {
        $lines = [
            $this->line('dn', $request->getDn()->toString()),
            $this->line('changetype', ChangeType::Delete->value),
        ];

        return implode($this->options->getLineEnding(), $lines) . $this->options->getLineEnding();
    }

    private function modifyBlock(ModifyRequest $request): string
    {
        $lines = [
            $this->line('dn', $request->getDn()->toString()),
            $this->line('changetype', ChangeType::Modify->value),
        ];

        foreach ($request->getChanges() as $change) {
            $lines = array_merge(
                $lines,
                $this->modSpecLines($change),
            );
        }

        return implode($this->options->getLineEnding(), $lines) . $this->options->getLineEnding();
    }

    /**
     * @return list<string>
     */
    private function modSpecLines(Change $change): array
    {
        $op = match ($change->getType()) {
            Change::TYPE_ADD => ModSpecOp::Add->value,
            Change::TYPE_DELETE => ModSpecOp::Delete->value,
            Change::TYPE_REPLACE => ModSpecOp::Replace->value,
            default => throw new LogicException(sprintf(
                'Unknown Change type %d.',
                $change->getType(),
            )),
        };
        $attribute = $change->getAttribute();
        $attrName = $attribute->getDescription();

        $lines = [$this->line($op, $attrName)];

        foreach ($attribute->getValues() as $value) {
            $lines[] = $this->line(
                $attrName,
                $value,
            );
        }

        $lines[] = '-';

        return $lines;
    }

    private function modRdnBlock(ModifyDnRequest $request): string
    {
        $lines = [
            $this->line('dn', $request->getDn()->toString()),
            $this->line('changetype', ChangeType::ModRdn->value),
            $this->line('newrdn', $request->getNewRdn()->toString()),
            $this->line('deleteoldrdn', $request->getDeleteOldRdn() ? '1' : '0'),
        ];

        $newParent = $request->getNewParentDn();

        if ($newParent !== null) {
            $lines[] = $this->line(
                'newsuperior',
                $newParent->toString(),
            );
        }

        return implode($this->options->getLineEnding(), $lines) . $this->options->getLineEnding();
    }

    /**
     * @return list<string>
     */
    private function attributeLines(Attribute $attribute): array
    {
        return array_values(array_map(
            fn(string $value): string => $this->line(
                $attribute->getDescription(),
                $value,
            ),
            $attribute->getValues(),
        ));
    }

    private function line(
        string $attribute,
        string $value,
    ): string {
        if ($value === '') {
            return $attribute . ':';
        }
        if ($this->needsBase64($value)) {
            return $this->fold($attribute . ':: ' . base64_encode($value));
        }

        return $this->fold($attribute . ': ' . $value);
    }

    /**
     * A value is not SAFE-STRING (RFC 2849 §2) when it begins with a space, ':' or '<', ends with a space, or holds a
     * NUL/CR/LF or any non-ASCII byte.
     */
    private function needsBase64(string $value): bool
    {
        $first = $value[0];

        if ($first === ' ' || $first === ':' || $first === '<') {
            return true;
        }
        if ($value[strlen($value) - 1] === ' ') {
            return true;
        }

        return preg_match('/[^\x01-\x7F]|[\x0A\x0D]/', $value) === 1;
    }

    private function fold(string $line): string
    {
        $maxLineLength = $this->options->getMaxLineLength();

        if (!$this->options->isLineFolding() || strlen($line) <= $maxLineLength) {
            return $line;
        }

        $folded = substr($line, 0, $maxLineLength);
        $continuationLength = max(1, $maxLineLength - 1);

        foreach (str_split(substr($line, $maxLineLength), $continuationLength) as $chunk) {
            $folded .= $this->options->getLineEnding() . ' ' . $chunk;
        }

        return $folded;
    }
}
