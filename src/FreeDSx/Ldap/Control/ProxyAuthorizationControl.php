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

use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
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
     * Keeps a received authzId that is not a valid form, to be refused when it is used rather than when decoded.
     */
    public static function unparsed(
        string $rawAuthzId,
        bool $criticality,
    ): self {
        $control = new self(
            AuthzId::anonymous(),
            $criticality,
        );
        $control->rawAuthzId = $rawAuthzId;
        $control->authzId = null;

        return $control;
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
}
