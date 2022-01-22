<?php

declare(strict_types=1);

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingResponse;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;

require __DIR__ . '/../../vendor/autoload.php';

class LdapServerPagingHandler implements PagingHandlerInterface
{
    public function page(
        PagingRequest $pagingRequest,
        RequestContext $context
    ): PagingResponse {
        $i = 0;

        $entries = [];
        while ($i < $pagingRequest->getSize()) {
            $i++;
            $entries[] = Entry::fromArray(
                "cn=foo$i,dc=foo,dc=bar",
                [
                    'foo' => $i,
                    'bar' => $i,
                ]
            );
        }
        $entries = new Entries(...$entries);

        if ($pagingRequest->getIteration() === 3) {
            $this->logRequest(
                'paging',
                'Final response with ' . $entries->count() . ' entries'
            );

            return PagingResponse::makeFinal($entries);
        } else {
            $this->logRequest(
                'paging',
                'Regular response with '
                . $entries->count() . ' entries, iteration '
                . $pagingRequest->getIteration()
            );

            return PagingResponse::make(
                $entries,
                ($pagingRequest->getSize() * 3) - ($pagingRequest->getIteration() * $pagingRequest->getSize())
            );
        }
    }

    public function remove(
        PagingRequest $pagingRequest,
        RequestContext $context
    ): void {
        $this->logRequest(
            'remove',
            'On iteration ' . $pagingRequest->getIteration()
        );
    }

    private function logRequest(
        string $type,
        string $message
    ): void {
        echo "---$type--- $message" . PHP_EOL;
    }
}

class LdapServerRequestHandler extends GenericRequestHandler
{
    private $users = [
        'cn=user,dc=foo,dc=bar' => '12345',
    ];

    public function bind(string $username, string $password): bool
    {
        $this->logRequest(
            'bind',
            "username => $username, password => $password"
        );

        return isset($this->users[$username])
            && $this->users[$username] === $password;
    }

    public function add(RequestContext $context, AddRequest $add): void
    {
        $attrLog = [];
        foreach ($add->getEntry()->getAttributes() as $attribute) {
            $attrLog[] = "{$attribute->getName()} => " . implode(
                ', ',
                $attribute->getValues()
            );
        }
        $attrLog = implode(', ', $attrLog);

        $this->logRequest(
            'add',
            "dn => {$add->getEntry()->getDn()->toString()}, Attributes: {$attrLog}"
        );
    }

    public function compare(RequestContext $context, CompareRequest $compare): bool
    {
        $filter = $compare->getFilter();

        $this->logRequest(
            'compare',
            "dn => {$compare->getDn()->toString()}, Name => {$filter->getAttribute()}, Value => {$filter->getValue()}"
        );

        return true;
    }

    public function delete(RequestContext $context, DeleteRequest $delete): void
    {
        $this->logRequest(
            'delete',
            "dn => {$delete->getDn()->toString()}"
        );
    }

    public function modify(RequestContext $context, ModifyRequest $modify): void
    {
        $modLog = [];
        foreach ($modify->getChanges() as $change) {
            $attribute = $change->getAttribute();
            $modLog[] = "({$change->getType()}){$attribute->getName()} => " . implode(
                ', ',
                $attribute->getValues()
            );
        }
        $modLog = implode(', ', $modLog);

        $this->logRequest(
            'modify',
            "dn => {$modify->getDn()->toString()}, Changes: $modLog"
        );
    }

    public function modifyDn(RequestContext $context, ModifyDnRequest $modifyDn): void
    {
        $dnLog = 'ParentDn => ' . $modifyDn->getNewParentDn()->toString();
        $dnLog .= ', ParentRdn => ' . $modifyDn->getNewRdn()->toString();

        $this->logRequest(
            'modify-dn',
            "dn => {$modifyDn->getDn()->toString()}, $dnLog"
        );
    }

    public function search(RequestContext $context, SearchRequest $search): Entries
    {
        $this->logRequest(
            'search',
            "base-dn => {$search->getBaseDn()->toString()}, filter => {$search->getFilter()->toString()}"
        );

        return new Entries(
            Entry::fromArray(
                'cn=user,dc=foo,dc=bar',
                [
                    'name' => 'user',
                ]
            )
        );
    }

    private function logRequest(
        string $type,
        string $message
    ): void {
        echo "---$type--- $message" . PHP_EOL;
    }
}

$sslKey = "/etc/ssl/private/slapd.key";
$sslCert = "/etc/ssl/certs/slapd.crt";

$transport = $argv[1] ?? 'tcp';
$handler = $argv[2] ?? null;
$useSsl = false;

if ($transport === 'ssl') {
    $transport = 'tcp';
    $useSsl = true;
}

$server = new LdapServer([
    'request_handler' => LdapServerRequestHandler::class,
    'port' => 3389,
    'transport' => $transport,
    'ssl_cert' => $sslCert,
    'ssl_cert_key' => $sslKey,
    'use_ssl' => $useSsl,
]);

if ($handler === 'paging') {
    $server->usePagingHandler(new LdapServerPagingHandler());
}

echo "server starting..." . PHP_EOL;

$server->run();
