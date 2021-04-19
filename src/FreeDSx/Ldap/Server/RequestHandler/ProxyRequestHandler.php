<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\RequestContext;

/**
 * Proxies requests to an LDAP server and returns the response. You should extend this to add your own constructor and
 * set the LDAP client options variable.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ProxyRequestHandler implements RequestHandlerInterface
{
    /**
     * @var LdapClient|null
     */
    protected $ldap;

    /**
     * @var array
     */
    protected $options = [];

    /**
     * @param string $username
     * @param string $password
     * @return bool
     * @throws OperationException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     * @throws \FreeDSx\Ldap\Exception\ConnectionException
     * @throws \FreeDSx\Ldap\Exception\ProtocolException
     * @throws \FreeDSx\Ldap\Exception\ReferralException
     * @throws \FreeDSx\Ldap\Exception\UnsolicitedNotificationException
     * @throws \FreeDSx\Sasl\Exception\SaslException
     * @throws \FreeDSx\Socket\Exception\ConnectionException
     * @throws \Throwable
     */
    public function bind(string $username, string $password): bool
    {
        try {
            return (bool) $this->ldap()->bind($username, $password);
        } catch (BindException $e) {
            throw new OperationException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param RequestContext $context
     * @param ModifyRequest $modify
     * @throws BindException
     * @throws OperationException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     * @throws \FreeDSx\Ldap\Exception\ConnectionException
     * @throws \FreeDSx\Ldap\Exception\ProtocolException
     * @throws \FreeDSx\Ldap\Exception\ReferralException
     * @throws \FreeDSx\Ldap\Exception\UnsolicitedNotificationException
     * @throws \FreeDSx\Sasl\Exception\SaslException
     * @throws \FreeDSx\Socket\Exception\ConnectionException
     * @throws \Throwable
     */
    public function modify(RequestContext $context, ModifyRequest $modify): void
    {
        $this->ldap()->sendAndReceive($modify, ...$context->controls()->toArray());
    }

    /**
     * @param RequestContext $context
     * @param ModifyDnRequest $modifyDn
     * @throws BindException
     * @throws OperationException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     * @throws \FreeDSx\Ldap\Exception\ConnectionException
     * @throws \FreeDSx\Ldap\Exception\ProtocolException
     * @throws \FreeDSx\Ldap\Exception\ReferralException
     * @throws \FreeDSx\Ldap\Exception\UnsolicitedNotificationException
     * @throws \FreeDSx\Sasl\Exception\SaslException
     * @throws \FreeDSx\Socket\Exception\ConnectionException
     * @throws \Throwable
     */
    public function modifyDn(RequestContext $context, ModifyDnRequest $modifyDn): void
    {
        $this->ldap()->sendAndReceive($modifyDn, ...$context->controls()->toArray());
    }

    /**
     * @param RequestContext $context
     * @param DeleteRequest $delete
     * @throws BindException
     * @throws OperationException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     * @throws \FreeDSx\Ldap\Exception\ConnectionException
     * @throws \FreeDSx\Ldap\Exception\ProtocolException
     * @throws \FreeDSx\Ldap\Exception\ReferralException
     * @throws \FreeDSx\Ldap\Exception\UnsolicitedNotificationException
     * @throws \FreeDSx\Sasl\Exception\SaslException
     * @throws \FreeDSx\Socket\Exception\ConnectionException
     * @throws \Throwable
     */
    public function delete(RequestContext $context, DeleteRequest $delete): void
    {
        $this->ldap()->sendAndReceive($delete, ...$context->controls()->toArray());
    }

    /**
     * @param RequestContext $context
     * @param AddRequest $add
     * @throws BindException
     * @throws OperationException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     * @throws \FreeDSx\Ldap\Exception\ConnectionException
     * @throws \FreeDSx\Ldap\Exception\ProtocolException
     * @throws \FreeDSx\Ldap\Exception\ReferralException
     * @throws \FreeDSx\Ldap\Exception\UnsolicitedNotificationException
     * @throws \FreeDSx\Sasl\Exception\SaslException
     * @throws \FreeDSx\Socket\Exception\ConnectionException
     * @throws \Throwable
     */
    public function add(RequestContext $context, AddRequest $add): void
    {
        $this->ldap()->sendAndReceive($add, ...$context->controls()->toArray());
    }

    /**
     * @param RequestContext $context
     * @param SearchRequest $search
     * @return Entries
     * @throws BindException
     * @throws OperationException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     * @throws \FreeDSx\Ldap\Exception\ConnectionException
     * @throws \FreeDSx\Ldap\Exception\ProtocolException
     * @throws \FreeDSx\Ldap\Exception\ReferralException
     * @throws \FreeDSx\Ldap\Exception\UnsolicitedNotificationException
     * @throws \FreeDSx\Sasl\Exception\SaslException
     * @throws \FreeDSx\Socket\Exception\ConnectionException
     * @throws \Throwable
     */
    public function search(RequestContext $context, SearchRequest $search): Entries
    {
        return $this->ldap()->search($search, ...$context->controls()->toArray());
    }

    /**
     * @param RequestContext $context
     * @param CompareRequest $compare
     * @return bool
     * @throws BindException
     * @throws OperationException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     * @throws \FreeDSx\Ldap\Exception\ConnectionException
     * @throws \FreeDSx\Ldap\Exception\ProtocolException
     * @throws \FreeDSx\Ldap\Exception\ReferralException
     * @throws \FreeDSx\Ldap\Exception\UnsolicitedNotificationException
     * @throws \FreeDSx\Sasl\Exception\SaslException
     * @throws \FreeDSx\Socket\Exception\ConnectionException
     * @throws \Throwable
     */
    public function compare(RequestContext $context, CompareRequest $compare): bool
    {
        $response = $this->ldap()->sendAndReceive($compare, ...$context->controls()->toArray())->getResponse();
        if (!$response instanceof LdapResult) {
            throw new OperationException('The result was malformed.', ResultCode::PROTOCOL_ERROR);
        }

        return $response->getResultCode() === ResultCode::COMPARE_TRUE;
    }

    /**
     * @param RequestContext $context
     * @param ExtendedRequest $extended
     * @throws BindException
     * @throws OperationException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     * @throws \FreeDSx\Ldap\Exception\ConnectionException
     * @throws \FreeDSx\Ldap\Exception\ProtocolException
     * @throws \FreeDSx\Ldap\Exception\ReferralException
     * @throws \FreeDSx\Ldap\Exception\UnsolicitedNotificationException
     * @throws \FreeDSx\Sasl\Exception\SaslException
     * @throws \FreeDSx\Socket\Exception\ConnectionException
     * @throws \Throwable
     */
    public function extended(RequestContext $context, ExtendedRequest $extended): void
    {
        $this->ldap()->send($extended, ...$context->controls()->toArray());
    }

    /**
     * @param LdapClient $client
     */
    public function setLdapClient(LdapClient $client): void
    {
        $this->ldap = $client;
    }

    /**
     * @return LdapClient
     */
    protected function ldap(): LdapClient
    {
        if ($this->ldap === null) {
            $this->ldap = new LdapClient($this->options);
        }

        return $this->ldap;
    }
}
