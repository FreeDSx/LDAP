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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolations;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Carries request-scoped metadata (identity, controls) for write operations.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class WriteContext
{
    private WriteMode $mode;

    /**
     * @param WriteMode|null $mode The kind of write, a client's when omitted.
     */
    public function __construct(
        private TokenInterface $token,
        private ControlBag $controls,
        ?WriteMode $mode = null,
        private SchemaViolations $schemaViolations = new SchemaViolations(),
        private ?WriteControlEvaluator $controlEvaluator = null,
        private ControlBag $responseControls = new ControlBag(),
    ) {
        $this->mode = $mode ?? WriteMode::client();
    }

    /**
     * Build a context for a server-initiated write that bypasses {@see SchemaValidator}.
     */
    public static function system(
        TokenInterface $token,
        ControlBag $controls,
    ): self {
        return new self(
            $token,
            $controls,
            WriteMode::system(),
        );
    }

    /**
     * Build a context for a system write recording server-maintained state that leaves the modify metadata as it was.
     */
    public static function bookkeeping(
        TokenInterface $token,
        ControlBag $controls,
    ): self {
        return new self(
            $token,
            $controls,
            WriteMode::bookkeeping(),
        );
    }

    /**
     * Build a context for loading an entry as supplied, rather than composing one for a client.
     */
    public static function bulkLoad(
        TokenInterface $token,
        ControlBag $controls,
        BulkLoadOptions $bulkLoad,
    ): self {
        return new self(
            $token,
            $controls,
            WriteMode::bulkLoad($bulkLoad),
        );
    }

    public function getToken(): TokenInterface
    {
        return $this->token;
    }

    /**
     * Bound DN of the authenticated user, or null for anonymous.
     */
    public function getBoundDn(): ?string
    {
        return $this->token->getUsername();
    }

    /**
     * Effective authorization identity for this write.
     */
    public function getAuthzId(): AuthzId
    {
        return $this->token->getAuthzId();
    }

    public function isSystem(): bool
    {
        return $this->mode->isSystem();
    }

    /**
     * Whether the write leaves modifyTimestamp and modifiersName as they were.
     */
    public function keepsModifyMetadata(): bool
    {
        return $this->mode->keepsModifyMetadata();
    }

    public function getControls(): ControlBag
    {
        return $this->controls;
    }

    public function schemaViolations(): SchemaViolations
    {
        return $this->schemaViolations;
    }

    /**
     * Present when the entry is loaded as supplied, so attributes the source provided are kept rather than restamped.
     */
    public function bulkLoadOptions(): ?BulkLoadOptions
    {
        return $this->mode->bulkLoadOptions();
    }

    /**
     * Present when the write's controls are evaluated under its lock, as for a client request or a replayed record.
     */
    public function controlEvaluator(): ?WriteControlEvaluator
    {
        return $this->controlEvaluator;
    }

    /**
     * Controls the write adds to its response when it succeeds.
     */
    public function responseControls(): ControlBag
    {
        return $this->responseControls;
    }

    /**
     * The same context for a later transaction of one write, whose controls were evaluated in its first.
     *
     * @internal
     */
    public function withoutControlEvaluator(): self
    {
        return new self(
            $this->token,
            $this->controls,
            $this->mode,
            $this->schemaViolations,
            null,
            $this->responseControls,
        );
    }
}
