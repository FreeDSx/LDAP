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

namespace FreeDSx\Ldap\Server\Backend\Write;

/**
 * The kind of write being made, which decides the checks it passes and the metadata it stamps.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class WriteMode
{
    private function __construct(
        private bool $isSystem,
        private bool $keepsModifyMetadata = false,
        private ?BulkLoadOptions $bulkLoad = null,
    ) {}

    /**
     * A write a client requested.
     */
    public static function client(): self
    {
        return new self(false);
    }

    /**
     * A server-initiated write that bypasses {@see SchemaValidator}.
     */
    public static function system(): self
    {
        return new self(true);
    }

    /**
     * A system write recording server-maintained state that leaves the modify metadata as it was.
     */
    public static function bookkeeping(): self
    {
        return new self(
            true,
            keepsModifyMetadata: true,
        );
    }

    /**
     * Loading an entry as supplied, rather than composing one for a client.
     */
    public static function bulkLoad(BulkLoadOptions $options): self
    {
        return new self(
            true,
            bulkLoad: $options,
        );
    }

    public function isSystem(): bool
    {
        return $this->isSystem;
    }

    /**
     * Whether the write leaves modifyTimestamp and modifiersName as they were.
     */
    public function keepsModifyMetadata(): bool
    {
        return $this->keepsModifyMetadata;
    }

    /**
     * Present when the entry is loaded as supplied, keeping the attributes its source provided instead of restamping.
     */
    public function bulkLoadOptions(): ?BulkLoadOptions
    {
        return $this->bulkLoad;
    }
}
