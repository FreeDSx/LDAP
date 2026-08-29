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

namespace FreeDSx\Ldap\Server\Backend\Write\Routing;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\AccessControl\OperationTargetDn;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\GeneratedEntry;

use function sprintf;

/**
 * Keeps a write off the entries the server generates that don't live in storage.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class GeneratedEntryGuard
{
    /**
     * @throws OperationException
     */
    public function assertWritable(
        RequestInterface $request,
        WriteContext $context,
    ): void {
        $this->assertNotGenerated($request);
        $this->assertParentIsNotGenerated(
            $request,
            $context,
        );
    }

    /**
     * Refused explicitly rather than reported missing incidentally.
     *
     * @throws OperationException
     */
    private function assertNotGenerated(RequestInterface $request): void
    {
        foreach ($this->targetDnsOf($request) as $dn) {
            $generated = GeneratedEntry::at($dn);
            if ($generated === null) {
                continue;
            }

            throw new OperationException(
                sprintf(
                    'The %s cannot be written to.',
                    $generated->label(),
                ),
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }
    }

    /**
     * A generated entry stores nothing. The RootDSE holds only naming contexts.
     *
     * @throws OperationException
     */
    private function assertParentIsNotGenerated(
        RequestInterface $request,
        WriteContext $context,
    ): void {
        $generated = GeneratedEntry::at($this->newParentOf($request));
        if ($generated === null) {
            return;
        }
        // A naming context is a child of the RootDSE, which only a server-initiated write may create.
        if ($generated === GeneratedEntry::RootDse && $context->isSystem()) {
            return;
        }

        throw new OperationException(
            sprintf(
                'An entry cannot be placed beneath the %s.',
                $generated->label(),
            ),
            ResultCode::UNWILLING_TO_PERFORM,
        );
    }

    /**
     * A rename is held to both ends, since it can land an entry on a name the server generates.
     *
     * @return list<Dn>
     */
    private function targetDnsOf(RequestInterface $request): array
    {
        $target = OperationTargetDn::of($request);
        if ($target === null) {
            return [];
        }

        return $request instanceof ModifyDnRequest
            ? [$target, OperationTargetDn::resultOf($request)]
            : [$target];
    }

    /**
     * The parent the write names for the entry, or null when it names none.
     */
    private function newParentOf(RequestInterface $request): ?Dn
    {
        return match (true) {
            $request instanceof AddRequest => $request->getEntry()
                ->getDn()
                ->getParent(),
            $request instanceof ModifyDnRequest => $request->getNewParentDn(),
            default => null,
        };
    }
}
