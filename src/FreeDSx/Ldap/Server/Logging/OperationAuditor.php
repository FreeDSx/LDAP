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

namespace FreeDSx\Ldap\Server\Logging;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\AccessControl\OperationTargetDn;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolations;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Builds the per-operation audit event shape and routes it through {@see EventLogger}.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class OperationAuditor
{
    public function __construct(private EventLogger $eventLogger) {}

    public function recordWriteSuccess(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        $request = $message->getRequest();
        $operationType = OperationType::fromRequest($request);

        if ($operationType === null) {
            return;
        }

        $event = ServerEvent::fromWriteOperationType($operationType);

        if ($event === null) {
            return;
        }

        $this->eventLogger->record(
            $event,
            [
                EventContext::OPERATION => $operationType->value,
                EventContext::TARGET => $this->writeTargetFor($request),
            ],
            subject: $token,
            message: $message,
        );
    }

    public function recordCompareCompleted(
        LdapMessageRequest $message,
        bool $match,
        TokenInterface $token,
    ): void {
        $request = $message->getRequest();

        if (!$request instanceof CompareRequest) {
            return;
        }

        $this->eventLogger->record(
            ServerEvent::CompareCompleted,
            [
                EventContext::MATCH => $match,
                EventContext::TARGET => [
                    EventContext::DN => $request->getDn()->toString(),
                    EventContext::ATTRIBUTE => $request->getFilter()->getAttribute(),
                ],
            ],
            subject: $token,
            message: $message,
        );
    }

    public function recordSearchSuccess(
        LdapMessageRequest $message,
        int $entriesReturned,
        TokenInterface $token,
    ): void {
        $request = $message->getRequest();

        if (!$request instanceof SearchRequest) {
            return;
        }

        $this->eventLogger->record(
            ServerEvent::SearchAuthorized,
            [
                EventContext::ENTRIES_RETURNED => $entriesReturned,
                EventContext::TARGET => $this->searchTarget($request),
            ],
            subject: $token,
            message: $message,
        );
    }

    public function recordSearchFailure(
        LdapMessageRequest $message,
        OperationException $exception,
        TokenInterface $token,
    ): void {
        $event = ServerEvent::fromOperationException(
            $exception,
            ServerEvent::AuthorizationDeniedRead,
        );

        if ($event === null) {
            return;
        }

        $request = $message->getRequest();

        if (!$request instanceof SearchRequest) {
            return;
        }

        $this->eventLogger->recordFailure(
            $event,
            $exception,
            [EventContext::TARGET => $this->searchTarget($request)],
            subject: $token,
            message: $message,
        );
    }

    public function recordCompareFailure(
        LdapMessageRequest $message,
        OperationException $exception,
        TokenInterface $token,
    ): void {
        $event = ServerEvent::fromOperationException(
            $exception,
            ServerEvent::AuthorizationDeniedRead,
        );

        $request = $message->getRequest();

        if ($event === null || !$request instanceof CompareRequest) {
            return;
        }

        $this->eventLogger->recordFailure(
            $event,
            $exception,
            [
                EventContext::TARGET => [
                    EventContext::DN => $request->getDn()->toString(),
                    EventContext::ATTRIBUTE => $request->getFilter()->getAttribute(),
                ],
            ],
            subject: $token,
            message: $message,
        );
    }

    public function recordPasswordModifySuccess(
        LdapMessageRequest $message,
        Dn $targetDn,
        TokenInterface $token,
    ): void {
        $this->eventLogger->record(
            ServerEvent::PasswordModifySuccess,
            [
                EventContext::TARGET => [EventContext::DN => $targetDn->toString()],
            ],
            subject: $token,
            message: $message,
        );
    }

    public function recordPasswordModifyFailure(
        LdapMessageRequest $message,
        OperationException $exception,
        ?Dn $targetDn,
        TokenInterface $token,
    ): void {
        $event = ServerEvent::fromOperationException(
            $exception,
            ServerEvent::AuthorizationDeniedWrite,
            ServerEvent::PasswordModifyFailed,
        );

        if ($event === null) {
            return;
        }

        $context = [];

        if ($targetDn !== null) {
            $context[EventContext::TARGET] = [EventContext::DN => $targetDn->toString()];
        }

        $this->eventLogger->recordFailure(
            $event,
            $exception,
            $context,
            subject: $token,
            message: $message,
        );
    }

    public function recordFailure(
        LdapMessageRequest $message,
        OperationException $exception,
        TokenInterface $token,
    ): void {
        $event = ServerEvent::fromOperationException(
            $exception,
            ServerEvent::AuthorizationDeniedWrite,
        );

        if ($event === null) {
            return;
        }

        $this->eventLogger->recordFailure(
            $event,
            $exception,
            $this->writeEventContext($message->getRequest()),
            subject: $token,
            message: $message,
        );
    }

    /**
     * Emits a schema.violation event for each validator violation recorded during the write.
     */
    public function recordSchemaViolations(
        SchemaViolations $violations,
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        foreach ($violations->all() as $recorded) {
            $this->eventLogger->record(
                ServerEvent::SchemaViolation,
                $this->writeEventContext(
                    $message->getRequest(),
                    [
                        EventContext::VALIDATION_MODE => $recorded->disposition->value,
                        EventContext::RESULT_CODE => $recorded->violation->code,
                        EventContext::REASON => $recorded->violation->message,
                    ],
                ),
                subject: $token,
                message: $message,
            );
        }
    }

    /**
     * @param array<string, mixed> $extra
     * @return array<string, mixed>
     */
    private function writeEventContext(
        RequestInterface $request,
        array $extra = [],
    ): array {
        $context = [EventContext::TARGET => $this->writeTargetFor($request)];
        $operationType = OperationType::fromRequest($request);

        if ($operationType !== null) {
            $context[EventContext::OPERATION] = $operationType->value;
        }

        return array_merge(
            $context,
            $extra,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function searchTarget(SearchRequest $request): array
    {
        return [
            EventContext::BASE_DN => (string) $request->getBaseDn(),
            EventContext::SCOPE => $request->getScope(),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function writeTargetFor(RequestInterface $request): array
    {
        if ($request instanceof ModifyDnRequest) {
            return $this->modifyDnTarget($request);
        }

        return [EventContext::DN => OperationTargetDn::of($request)?->toString() ?? ''];
    }

    /**
     * @return array<string, mixed>
     */
    private function modifyDnTarget(ModifyDnRequest $request): array
    {
        $target = [
            EventContext::DN => $request->getDn()->toString(),
            EventContext::NEW_RDN => $request->getNewRdn()->toString(),
        ];
        $newSuperior = $request->getNewParentDn();

        if ($newSuperior !== null) {
            $target[EventContext::NEW_SUPERIOR_DN] = $newSuperior->toString();
        }

        return $target;
    }
}
