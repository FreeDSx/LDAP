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

namespace FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;

/**
 * Represents a proxied authorization control. RFC 4370.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ProxyAuthorizationControl extends Control
{
    private string $rawAuthzId;

    private ?AuthzId $authzId;

    public function __construct(
        AuthzId $authzId,
        bool $criticality = true,
    ) {
        $this->setAuthzId($authzId);

        parent::__construct(
            self::OID_PROXY_AUTHORIZATION,
            $criticality,
        );
    }

    /**
     * The authorization identity to assume; lazily parsed from the raw value when decoded from a request.
     *
     * @throws InvalidArgumentException when the raw wire value is not a valid authzId form (e.g. a malformed request)
     */
    public function getAuthzId(): AuthzId
    {
        return $this->authzId ??= AuthzId::fromString($this->rawAuthzId);
    }

    /**
     * The raw authzId wire value, which may be an invalid form when decoded from a request.
     */
    public function getRawAuthzId(): string
    {
        return $this->rawAuthzId;
    }

    public function setAuthzId(AuthzId $authzId): self
    {
        $this->authzId = $authzId;
        $this->rawAuthzId = $authzId->toString();

        return $this;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = $this->rawAuthzId;

        return parent::toAsn1();
    }

    /**
     * {@inheritDoc}
     *
     * @param AbstractType<mixed> $type
     */
    public static function fromAsn1(AbstractType $type): static
    {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException(sprintf(
                'Expected a sequence type for a proxy authorization control, but received: %s',
                get_class($type),
            ));
        }

        [1 => $criticality, 2 => $rawAuthzId] = self::parseAsn1ControlValues($type);

        // RFC 4370 3: the value is present even for an anonymous identity.
        if ($rawAuthzId === null) {
            throw new ProtocolException('The proxied authorization control must have a value.');
        }

        try {
            return new static(
                AuthzId::fromString($rawAuthzId),
                $criticality,
            );
        } catch (InvalidArgumentException) {
            // Preserve a malformed value so it surfaces as an authorization denial rather than a decode failure.
            $control = new static(
                AuthzId::anonymous(),
                $criticality,
            );
            $control->rawAuthzId = $rawAuthzId;
            $control->authzId = null;

            return $control;
        }
    }
}
