<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Protocol\Factory;

use PhpDs\Ldap\Asn1\Type\AbstractType;
use PhpDs\Ldap\Exception\InvalidArgumentException;
use PhpDs\Ldap\Exception\ProtocolException;
use PhpDs\Ldap\Protocol\ProtocolElementInterface;

/**
 * Resolves protocol operation tags and ASN1 to specific classes.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class OperationFactory
{
    /**
     * @var string[]
     */
    protected static $map = [
        0 => 'PhpDs\Ldap\Operation\Request\BindRequest',
        1 => 'PhpDs\Ldap\Operation\Response\BindResponse',
        2 => 'PhpDs\Ldap\Operation\Request\UnbindRequest',
        3 => 'PhpDs\Ldap\Operation\Request\SearchRequest',
        4 => 'PhpDs\Ldap\Operation\Response\SearchResultEntry',
        5 => 'PhpDs\Ldap\Operation\Response\SearchResultDone',
        6 => 'PhpDs\Ldap\Operation\Request\ModifyRequest',
        7 => 'PhpDs\Ldap\Operation\Response\ModifyResponse',
        8 => 'PhpDs\Ldap\Operation\Request\AddRequest',
        9 => 'PhpDs\Ldap\Operation\Response\AddResponse',
        10 => 'PhpDs\Ldap\Operation\Request\DeleteRequest',
        11 => 'PhpDs\Ldap\Operation\Response\DeleteResponse',
        12 => 'PhpDs\Ldap\Operation\Request\ModifyDnRequest',
        13 => 'PhpDs\Ldap\Operation\Response\ModifyDnResponse',
        14 => 'PhpDs\Ldap\Operation\Request\CompareRequest',
        15 => 'PhpDs\Ldap\Operation\Response\CompareResponse',
        19 => 'PhpDs\Ldap\Operation\Response\SearchResultReference',
        23 => 'PhpDs\Ldap\Operation\Request\ExtendedRequest',
        24 => 'PhpDs\Ldap\Operation\Response\ExtendedResponse',
        25 => 'PhpDs\Ldap\Operation\Response\IntermediateResponse',
    ];

    /**
     * Retrieve the Request Response/Request class given a protocol number and the ASN1.
     *
     * @param AbstractType $asn1
     * @return ProtocolElementInterface
     * @throws ProtocolException
     */
    public static function get(AbstractType $asn1)
    {
        if (!isset(self::$map[$asn1->getTagNumber()])) {
            throw new ProtocolException(sprintf(
                'There is no class mapped for protocol operation %s.',
                $asn1->getTagNumber()
            ));
        }

        return call_user_func(self::$map[$asn1->getTagNumber()].'::fromAsn1', $asn1);
    }

    /**
     * Check whether a specific operation is mapped to a class.
     *
     * @param int $operation
     * @return bool
     */
    public static function has(int $operation) : bool
    {
        return isset(self::$map[$operation]);
    }

    /**
     * Set a specific class for an operation. It must implement ProtocolElementInterface.
     *
     * @param int $operation
     * @param $className
     */
    public static function set(int $operation, $className) : void
    {
        if (!class_exists($className)) {
            throw new InvalidArgumentException(sprintf(
               'The class for operation %s does not exist: %s',
               $operation,
               $className
            ));
        }
        if (!is_subclass_of($className, ProtocolElementInterface::class)) {
            throw new InvalidArgumentException(sprintf(
               'The class must implement ProtocolElementInterface, but it does not: %s',
               $className
            ));
        }
        self::$map[$operation] = $className;
    }
}
