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
    public function __construct(
        private TokenInterface $token,
        private ControlBag $controls,
        private bool $isSystem = false,
        private SchemaViolations $schemaViolations = new SchemaViolations(),
        private ?BulkLoadOptions $bulkLoad = null,
    ) {}

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
            isSystem: true,
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
            isSystem: true,
            bulkLoad: $bulkLoad,
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
        return $this->isSystem;
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
        return $this->bulkLoad;
    }
}
