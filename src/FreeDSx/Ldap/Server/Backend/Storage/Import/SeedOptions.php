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

namespace FreeDSx\Ldap\Server\Backend\Storage\Import;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Ldif\Url\LdifUrlResolverInterface;
use FreeDSx\Ldap\Ldif\Url\RefusingUrlResolver;

/**
 * Options for {@see \FreeDSx\Ldap\LdapServer::seed()}, the inverse of {@see Export\DumpOptions}.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SeedOptions
{
    public function __construct(
        private Dn $creatorDn = new Dn(''),
        private bool $ignoreValidation = false,
        private LdifUrlResolverInterface $urlResolver = new RefusingUrlResolver(),
        private bool $replaceExisting = false,
    ) {}

    public function getCreatorDn(): Dn
    {
        return $this->creatorDn;
    }

    /**
     * Recorded as creatorsName on every seeded entry.
     */
    public function setCreatorDn(Dn $creatorDn): self
    {
        $this->creatorDn = $creatorDn;

        return $this;
    }

    public function isIgnoreValidation(): bool
    {
        return $this->ignoreValidation;
    }

    /**
     * Loads content the current schema does not cover, such as a migration that predates it.
     */
    public function setIgnoreValidation(bool $ignoreValidation): self
    {
        $this->ignoreValidation = $ignoreValidation;

        return $this;
    }

    public function isReplaceExisting(): bool
    {
        return $this->replaceExisting;
    }

    /**
     * Overwrites an entry already at the same DN, rather than refusing the seed with entryAlreadyExists.
     *
     * Supply entryUUID for every entry replaced. An omitted one is generated fresh, which reads as a delete
     * and an add to anything keyed on it.
     */
    public function setReplaceExisting(bool $replaceExisting): self
    {
        $this->replaceExisting = $replaceExisting;

        return $this;
    }

    public function getUrlResolver(): LdifUrlResolverInterface
    {
        return $this->urlResolver;
    }

    /**
     * Enables RFC 2849 URL values, which let the LDIF name content the server then reads on its behalf.
     */
    public function setUrlResolver(LdifUrlResolverInterface $urlResolver): self
    {
        $this->urlResolver = $urlResolver;

        return $this;
    }
}
