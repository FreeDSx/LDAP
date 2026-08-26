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

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\SystemChange\SystemChangeWriterInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordModifyAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyChangeGuard;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;

/**
 * Enforces password policy on a plain ldapmodify of userPassword, delegating the write to a decorated handler.
 */
final readonly class PasswordPolicyWriteHandler implements WriteHandlerInterface
{
    /**
     * Change types that set a new password value.
     */
    private const SET_TYPES = [
        Change::TYPE_ADD,
        Change::TYPE_REPLACE,
    ];

    public function __construct(
        private ReadBackendInterface $backend,
        private WriteHandlerInterface $writes,
        private PasswordPolicyChangeGuard $changeGuard,
        private SystemChangeWriterInterface $systemChangeWriter,
        private PasswordHashService $hashService = new PasswordHashService(),
    ) {}

    /**
     * Anything not setting a password is nothing this has an opinion about.
     *
     * @throws OperationException
     */
    public function handle(
        WriteRequestInterface $request,
        WriteContext $context,
    ): void {
        if ($this->newPasswordsFor($request) === []) {
            $this->writes->handle($request, $context);

            return;
        }

        match (true) {
            $request instanceof AddCommand => $this->handleAdd($request, $context),
            $request instanceof UpdateCommand => $this->handleUpdate($request, $context),
            default => $this->writes->handle($request, $context),
        };
    }

    /**
     * Setting a password while creating an entry is a password change like any other (draft-behera-10 section 4.2),
     * so it is held to the same policy. The entry has no prior state, so only quality can reject it.
     *
     * @throws OperationException
     */
    private function handleAdd(
        AddCommand $request,
        WriteContext $context,
    ): void {
        $newPasswords = $this->entryPasswordValues($request->entry);
        if ($newPasswords === []) {
            $this->writes->handle(
                $request,
                $context,
            );

            return;
        }

        $deltas = $this->changeGuard->enforceAll($this->attemptsFor(
            $request->entry,
            $newPasswords,
            null,
            $this->isSelf($context, $request->entry->getDn()),
            isNewEntry: true,
        ));

        // Carried on the command rather than written after, so the entry is never stored without the state governing
        // it, and rather than folded into the entry, so validation still judges only what the requester supplied.
        $this->writes->handle(
            new AddCommand(
                $request->entry,
                $deltas->changes,
            ),
            $context,
        );
    }

    /**
     * @throws OperationException
     */
    private function handleUpdate(
        UpdateCommand $request,
        WriteContext $context,
    ): void {
        $newPasswords = $this->userPasswordValues($request, self::SET_TYPES);
        $entry = $this->backend->get($request->dn);
        if ($newPasswords === [] || $entry === null) {
            $this->writes->handle(
                $request,
                $context,
            );

            return;
        }

        $isSelf = $this->isSelf(
            $context,
            $request->dn,
        );
        $deltas = $this->changeGuard->enforceAll($this->attemptsFor(
            $entry,
            $newPasswords,
            $this->userPasswordValues($request, [Change::TYPE_DELETE])[0] ?? null,
            $isSelf,
        ));

        $this->writes->handle(
            $request,
            $context,
        );
        $this->systemChangeWriter->write(
            $request->dn,
            $deltas,
        );

        // A successful self-change satisfies any pwdReset requirement. no re-bind needed.
        $token = $context->getToken();
        if ($isSelf && $token instanceof AuthenticatedTokenInterface) {
            $token->clearMustChangePassword();
        }
    }

    /**
     * Every value being set must satisfy policy.
     *
     * @param non-empty-list<string> $newPasswords
     * @return non-empty-list<PasswordModifyAttempt>
     */
    private function attemptsFor(
        Entry $target,
        array $newPasswords,
        ?string $oldPassword,
        bool $isSelf,
        bool $isNewEntry = false,
    ): array {
        return array_map(
            fn(string $newPassword): PasswordModifyAttempt => new PasswordModifyAttempt(
                target: $target,
                newPassword: $newPassword,
                oldPassword: $oldPassword,
                isSelf: $isSelf,
                passwordIsCleartext: !$this->hashService->isHashed($newPassword),
                isNewEntry: $isNewEntry,
            ),
            $newPasswords,
        );
    }

    /**
     * New password values a command sets, for whichever operation carries them.
     *
     * @return list<string>
     */
    private function newPasswordsFor(WriteRequestInterface $request): array
    {
        return match (true) {
            $request instanceof AddCommand => $this->entryPasswordValues($request->entry),
            $request instanceof UpdateCommand => $this->userPasswordValues($request, self::SET_TYPES),
            default => [],
        };
    }

    /**
     * @return list<string>
     */
    private function entryPasswordValues(Entry $entry): array
    {
        return array_values(
            $entry->get(AttributeTypeOid::NAME_USER_PASSWORD)?->getValues() ?? [],
        );
    }

    /**
     * @param list<int> $types
     * @return list<string>
     */
    private function userPasswordValues(
        UpdateCommand $command,
        array $types,
    ): array {
        $values = [];
        foreach ($command->changes as $change) {
            if (!$this->isUserPasswordChange($change)) {
                continue;
            }
            if (!in_array($change->getType(), $types, true)) {
                continue;
            }

            foreach ($change->getAttribute()->getValues() as $value) {
                $values[] = $value;
            }
        }

        return $values;
    }

    private function isUserPasswordChange(Change $change): bool
    {
        return strcasecmp(
            $change->getAttribute()->getName(),
            AttributeTypeOid::NAME_USER_PASSWORD,
        ) === 0;
    }

    private function isSelf(
        WriteContext $context,
        Dn $targetDn,
    ): bool {
        $boundDn = $context->getBoundDn();

        return $boundDn !== null
            && (new Dn($boundDn))->normalize()->toString() === $targetDn->normalize()->toString();
    }
}
