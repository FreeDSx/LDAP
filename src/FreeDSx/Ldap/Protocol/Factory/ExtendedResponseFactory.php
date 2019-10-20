<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;

/**
 * Used to instantiate specific extended response OIDs.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ExtendedResponseFactory
{
    /**
     * @var string[]
     */
    protected static $map = [
        ExtendedRequest::OID_PWD_MODIFY => PasswordModifyResponse::class,
    ];

    /**
     * Retrieve the Request Response/Request class given a protocol number and the ASN1.
     *
     * @param AbstractType $asn1
     * @param string $oid
     * @return ExtendedResponse
     * @throws ProtocolException
     */
    public function get(AbstractType $asn1, string $oid): ExtendedResponse
    {
        if (!self::has($oid)) {
            throw new ProtocolException(sprintf(
                'There is no extended response mapped for %s.',
                $oid
            ));
        }
        $responseConstruct = self::$map[$oid] . '::fromAsn1';
        if (!is_callable($responseConstruct)) {
            throw new RuntimeException(sprintf(
                'The extended response construct is not callable: %s',
                $responseConstruct
            ));
        }

        return call_user_func($responseConstruct, $asn1);
    }

    /**
     * Check whether a specific control OID is mapped to a class.
     *
     * @param string $oid
     * @return bool
     */
    public function has(string $oid)
    {
        return isset(self::$map[$oid]);
    }

    /**
     * Set a specific class for an operation. It must implement ProtocolElementInterface.
     */
    public static function set(string $oid, string $className): void
    {
        if (!class_exists($className)) {
            throw new InvalidArgumentException(sprintf(
                'The class for the extended response %s does not exist: %s',
                $oid,
                $className
            ));
        }
        if (!is_subclass_of($className, ExtendedResponse::class)) {
            throw new InvalidArgumentException(sprintf(
                'The class must extend the ExtendedResponse, but it does not: %s',
                $className
            ));
        }
        self::$map[$oid] = $className;
    }
}
