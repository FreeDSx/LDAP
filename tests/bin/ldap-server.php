<?php

declare(strict_types=1);

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WritableBackendTrait;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\ServerOptions;

require __DIR__ . '/../../vendor/autoload.php';

class LdapServerBackend implements WritableLdapBackendInterface, PasswordAuthenticatableInterface
{
    use WritableBackendTrait;

    /**
     * @var array<string, string>
     */
    private array $users = [
        'cn=user,dc=foo,dc=bar' => '12345',
    ];

    public function search(
        SearchRequest $request,
        ControlBag $controls = new ControlBag(),
    ): EntryStream {
        $baseDn = $request->getBaseDn()?->toString() ?? '';

        $this->logRequest(
            'search',
            "base-dn => {$baseDn}, filter => {$request->getFilter()->toString()}"
        );

        return new EntryStream($this->yieldSearchResults($baseDn));
    }

    private function yieldSearchResults(string $baseDn): Generator
    {
        yield Entry::fromArray(
            $baseDn,
            [
                'objectClass' => 'inetOrgPerson',
                'cn' => 'user',
                'name' => 'user',
                'foo' => 'bar',
            ]
        );
    }

    public function get(Dn $dn): ?Entry
    {
        return Entry::fromArray(
            $dn->toString(),
            [
                'foo' => 'bar',
            ]
        );
    }

    public function compare(
        Dn $dn,
        EqualityFilter $filter,
    ): bool {
        $entry = $this->get($dn);

        if ($entry === null) {
            throw new OperationException(
                sprintf('No such object: %s', $dn->toString()),
                ResultCode::NO_SUCH_OBJECT,
            );
        }

        $attribute = $entry->get($filter->getAttribute());

        if ($attribute === null) {
            return false;
        }

        foreach ($attribute->getValues() as $value) {
            if (strcasecmp($value, $filter->getValue()) === 0) {
                return true;
            }
        }

        return false;
    }

    public function verifyPassword(
        string $name,
        string $password,
    ): bool {

        $this->logRequest(
            'bind',
            "username => $name, password => $password"
        );

        return isset($this->users[$name]) && $this->users[$name] === $password;
    }

    public function add(AddCommand $command): void
    {
        $entry = $command->entry;
        $attrLog = [];
        foreach ($entry->getAttributes() as $attribute) {
            $attrLog[] = "{$attribute->getName()} => " . implode(', ', $attribute->getValues());
        }

        $this->logRequest(
            'add',
            "dn => {$entry->getDn()->toString()}, Attributes: " . implode(', ', $attrLog)
        );
    }

    public function delete(DeleteCommand $command): void
    {
        $this->logRequest('delete', "dn => {$command->dn->toString()}");
    }

    public function update(UpdateCommand $command): void
    {
        $modLog = [];
        foreach ($command->changes as $change) {
            $attribute = $change->getAttribute();
            $modLog[] = "({$change->getType()}){$attribute->getName()} => " . implode(
                ', ',
                $attribute->getValues()
            );
        }

        $this->logRequest(
            'modify',
            "dn => {$command->dn->toString()}, Changes: " . implode(', ', $modLog)
        );
    }

    public function move(MoveCommand $command): void
    {
        $dnLog = 'ParentDn => ' . $command->newParent?->toString();
        $dnLog .= ', ParentRdn => ' . $command->newRdn->toString();

        $this->logRequest('modify-dn', "dn => {$command->dn->toString()}, $dnLog");
    }

    public function getPassword(
        string $username,
        string $mechanism,
    ): ?string {
        return $this->users[$username] ?? null;
    }

    private function logRequest(string $type, string $message): void
    {
        echo "---$type--- $message" . PHP_EOL;
    }
}

class LdapServerPagingBackend extends LdapServerBackend
{
    public function search(
        SearchRequest $request,
        ControlBag $controls = new ControlBag(),
    ): EntryStream {
        return new EntryStream($this->yieldPagingResults());
    }

    private function yieldPagingResults(): Generator
    {
        for ($i = 1; $i <= 300; $i++) {
            yield Entry::fromArray(
                "cn=foo$i,dc=foo,dc=bar",
                [
                    'foo' => (string) $i,
                    'bar' => (string) $i,
                ]
            );
        }
    }
}

$sslKey = __DIR__ . '/../resources/cert/slapd.key';
$sslCert = __DIR__ . '/../resources/cert/slapd.crt';

$transport = $argv[1] ?? 'tcp';
$handler = $argv[2] ?? null;
$useSsl = false;

if ($transport === 'ssl') {
    $transport = 'tcp';
    $useSsl = true;
}

$backend = $handler === 'paging'
    ? new LdapServerPagingBackend()
    : new LdapServerBackend();

$options = (new ServerOptions())
    ->setPort(10389)
    ->setTransport($transport)
    ->setUnixSocket(sys_get_temp_dir() . '/ldap.socket')
    ->setSslCert($sslCert)
    ->setSslCertKey($sslKey)
    ->setUseSsl($useSsl)
    ->setSocketAcceptTimeout(0.1)
    ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL));

if ($handler === 'sasl') {
    $options->setSaslMechanisms(
        ServerOptions::SASL_PLAIN,
        ServerOptions::SASL_CRAM_MD5,
        ServerOptions::SASL_SCRAM_SHA_256,
    );
}

$server = (new LdapServer($options))->useBackend($backend);

$server->run();
