SyncRepl
================

SyncRepl leverages Directory Synchronization described in RFC-4533. It was first implemented in OpenLDAP, but has implementations
in other directory servers. It can be used to track / sync changes against LDAP entries.

The sync process extends the LDAP search functionality and can contain any valid LDAP filter you want. There is an included
helper class in this library for performing a SyncRepl request more easily.

* [General Usage](#general-usage)
    * [The Polling Method](#the-polling-method)
    * [The Listen Method](#the-listen-method)
* [Sync Handlers](#sync-handlers)
    * [The Entry Handler](#the-entry-handler)
    * [The IdSet Handler](#the-idset-handler)
    * [The Referral Handler](#the-referral-handler)
    * [The Cookie Handler](#the-cookie-handler)
* [The Session Object](#the-session-object)
* [Cancelling a Sync](#cancelling-a-sync)
* [SyncRepl Class Methods](#syncrepl-class-methods)
    * [useFilter](#usefilter)
    * [useCookie](#usecookie)
    * [useCookieHandler](#usecookiehandler)
    * [useEntryHandler](#useentryhandler)
    * [useIdSetHandler](#useidsethandler)
    * [useReferralHandler](#usereferralhandler)

# General Usage

To use the SyncRepl helper class you can instantiate it from the main LdapClient class using the `syncRepl()` method:

```php
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Operations;

# The most simple way to start SyncRepl:
#   * Uses the default baseDn provided in the client options.
#   * Uses the LDAP filter '(objectClass=*)', which all return all entries.
$syncRepl = $client->syncRepl();

# Can optionally pass a specific filter as an argument.
# For example, only sync user changes.
$syncRepl = $client->syncRepl(Filters::equal('objectClass', 'user'));
```

There are two main methods for making use of the helper class listed below, depending on which better fits your needs.
There are also several methods available on the SyncRepl class for further customizing how it should work, which are also
defined further below.

## The Polling Method

The polling method iterates through all sync changes then stops. You would then call it at some future point using the
same sync session cookie to see what has changed since the last polling.

```php
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;

// Saving the cookie to a file.
// With the cookie handler, you determine where to save it.
$cookieFile = __DIR__ . '/.sync_cookie';

// Retrieve a previous sync cookie if you have one.
// If you provide a null cookie, the poll will return initial content.
$cookie = file_get_contents($cookieFile) ?: null;

$ldap
    ->syncRepl()
    ->useCookie($cookie)
    // The cookie may change at many points during a sync. This handler should react to the new cookie to save it off
    // somewhere to be used in the future.
    ->useCookieHandler(fn (string $cookie) => file_put_contents($cookieFile, $cookie))
    ->poll(function(SyncEntryResult $result) {
        $entry = $result->getEntry();
        $uuid = $result->getEntryUuid();
        
        // "Add" here means either it changed **or** was added.
        if ($result->isAdd()) {
       
        // This should represent an entry being modified...but in OpenLDAP, I have not seen this used?
        } elseif ($result->isModify()) {
        // The entry was removed. Note that the entry attributes will be empty in this case.
        // Use the UUID from the result to remove it on the sync side.
        } elseif ($result->isDelete()) {
        // The entry is present and has not changed.
        } elseif ($result->isPresent()) {
        }
    });
```

## The Listen Method

The listen method waits for sync changes in a never-ending search operation.

The handler closure receives a `SyncEntryResult` as its first argument and a `Session` as its optional second argument.
The `Session` object provides context about the current state of the sync, such as whether the initial refresh phase has
completed. See [The Session Object](#the-session-object) for more details.

```php
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Session;

// Saving the cookie to a file.
// With the cookie handler, you determine where to save it.
$cookieFile = __DIR__ . '/.sync_cookie';

// Retrieve a previous sync cookie if you have one.
// If you provide a null cookie, the poll will return initial content.
$cookie = file_get_contents($cookieFile) ?: null;

$ldap
    ->syncRepl()
    ->useCookie($cookie)
    // The cookie may change at many points during a sync. This handler should react to the new cookie to save it off
    // somewhere to be used in the future.
    ->useCookieHandler(fn (string $cookie) => file_put_contents($cookieFile, $cookie))
    ->listen(function(SyncEntryResult $result, Session $session) {
        // Entries received before isRefreshComplete() are initial content from the refresh phase.
        // Entries received after isRefreshComplete() are change notifications from the persist phase.
        if (!$session->isRefreshComplete()) {
            // Refresh phase: initial content delivery
            // Do what you wish with the initial data...
            return;
        }

        $entry = $result->getEntry();
        $uuid = $result->getEntryUuid();

        // Persist phase: change notifications.
        // "Add" here means either it changed **or** was added.
        if ($result->isAdd()) {

        // This should represent an entry being modified...but in OpenLDAP, I have not seen this used?
        } elseif ($result->isModify()) {
        // The entry was removed. Note that the entry attributes will be empty in this case.
        // Use the UUID from the result to remove it on the sync side.
        } elseif ($result->isDelete()) {
        }
    });
```

# Sync Handlers

There are three main handlers you can define to react to sync messages that are encountered. Not all are needed, as you
could choose to ignore referrals. However, you should take action on both Entry and IdSet changes.

## The Entry Handler

The Entry handler should always be defined. It is passed to either the `poll()` or `listen()` method directly, or can optionally
be passed to the `useEntryHandler()` method. This handler must be a closure that receives a `SyncEntryResult` as the first
argument and optionally a `Session` as the second argument. The `SyncEntryResult` represents a single sync entry change.

For more details, see [useEntryHandler](#useentryhandler) and [The Session Object](#the-session-object).

## The IdSet Handler

The IdSet handler is set using the `useIdSetHandler()` method. This handler must be a closure that receives a `SyncIdSetResult`
as the first argument. The `SyncIdSetResult` represents multiple entry changes in LDAP, however the change represented is
only one of: delete, present.

For more details, see [useIdSetHandler](#useidsethandler). You should define this handler to react to large LDAP sync changes. 

## The Referral Handler

The Referral handler is set using the `useReferralHandler()` method. This handler must be a closure that receives a `SyncReferralResult`
as the first argument. The `SyncReferralResult` represents an entry that has changed but is located on a different server via a referral.
If you do not want to sync referral information, these can be ignored.

For more details, see [useReferralHandler](#usereferralhandler).

## The Cookie Handler

The Cookie handler is set using the `useCookieHandler()` method. This handler must be a closure that receives a `string` cookie value
as the first argument. This handler is different from the others as it does not represent a sync change, but a change in
the sync session cookie. If you wish to restart this sync session at some later point, you should be defining this to save
the changed cookie somewhere and reload it before starting the sync again.

For more details, see [useCookieHandler](#usecookiehandler) and [useCookie](#usecookie).


# The Session Object

The `Session` object is passed as the second argument to the entry handler closure and provides context about the current
state of the sync operation.

## isRefreshComplete

In `listen()` mode the sync operates in two phases:

1. **Refresh phase** — The server delivers its initial content. Entries here represent the current state of the directory,
   not necessarily changes.
2. **Persist phase** — After the refresh completes, the server sends change notifications indefinitely as entries are
   added, modified, or deleted.

The `isRefreshComplete()` method returns `false` during the refresh phase and `true` once the server has signaled that
the refresh is done and the persist phase has begun. This is the reliable way to distinguish between the two phases:

```php
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Session;

$ldap
    ->syncRepl()
    ->listen(function(SyncEntryResult $result, Session $session) {
        if (!$session->isRefreshComplete()) {
            // Still in the refresh phase — skip or handle initial content.
            return;
        }

        // Persist phase — this is a real change notification.
    });
```

## getPhase

Returns the current sub-phase of the refresh, if the server has explicitly signaled one. This will be one of:

- `Session::PHASE_DELETE` — The server is using the refreshDelete strategy.
- `Session::PHASE_PRESENT` — The server is using the refreshPresent strategy.
- `null` — No explicit sub-phase is currently active.

Note that not all servers signal an explicit sub-phase before sending refresh entries (OpenLDAP does not), so
`getPhase()` returning `null` does not necessarily mean the refresh phase is complete. Use `isRefreshComplete()` instead
to reliably determine when the persist phase begins.

# Cancelling a Sync

Cancelling a sync provides a way to tell the server to gracefully end the sync operation. To initiate the cancellation
process, you must throw a `CancelRequestException` within one of the [sync handlers](#sync-handlers).

**Note**: By default, the handlers will not receive any further messages once a cancellation is issued. To continue to
receive messages until the server processes the cancellation, you can call `useContinueOnCancel()` on the SyncRepl client.

```php
use FreeDSx\Ldap\Exception\CancelRequestException;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;

$ldap
    ->syncRepl()
    ->listen(function(SyncEntryResult $result) {
        $entry = $result->getEntry();
        $uuid = $result->getEntryUuid();
        
        // Add some logic for when this should be thrown...
        // But this will initiate a cancellation.
        throw new CancelRequestException();
    });
```

# SyncRepl Class Methods

## useCookie

You can use the `useCookie()` method to explicitly set the cookie for the sync. The cookie is an opaque, binary value,
that is used to identify the sync. For instance, if you start the sync and want to later restart it, you could save the
cookie value somewhere then set it here with this method to restart the sync:

**Note**: This assumes that server will still accept the cookie as valid. It may not and decide to force an initial sync.

```php
# Set the cookie later to potentially resume the sync where you left off
# Continue with the getChanges() / hasChanges() like you normally would
$syncRepl->useCookie($cookie);
```

## useCookieHandler

This method takes a closure that can be used to save the cookie as it changes during the sync process. You will want to
use this if you plan to reuse a previous sync session.

Below is a very simple example of using this to save the cookie off to a local file:

```php
// Saving the cookie to a file.
// With the cookie handler, you determine where to save it.
$cookieFile = __DIR__ . '/.sync_cookie';

$syncRepl->useCookieHandler(
    fn (string $cookie) => file_put_contents(
        $cookieFile,
        $cookie,
    )
);
```

## useEntryHandler

This method takes a closure that reacts to a single entry change / sync. It is basically required if you want to get
anything useful from the sync. The closure receives a `SyncEntryResult` as the first argument and optionally a `Session`
as the second argument.

```php
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Session;

$syncRepl->useEntryHandler(function(SyncEntryResult $result, Session $session) {
    // The Entry object associated with this sync change.
    $result->getEntry();
    // The raw result state of the entry. See "SyncStateControl::STATE_*"
    $result->getState();
    // The raw LDAP message for this entry. Can get the result code / controls / etc.
    $result->getMessage();
    // Whether the initial refresh phase has completed (listen() mode only).
    $session->isRefreshComplete();
});
```

## useIdSetHandler

This method defines a closure that handles IdSets received during the sync process. IdSets are arrays of entry UUIDs
that represent a large set of entry deletes or entries still present, but do not contain other information about the
records (such as the full Entry object).

You should define a handler for this, otherwise you may miss important large sync changes.

```php
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;

$syncRepl->useIdSetHandler(function(SyncIdSetResult $result) {
    // The array of UUID entry strings that have changed.
    $result->getEntryUuids();
    // Are the entries represented present?
    $result->isPresent();
    // Are the entries represented deleted?
    $result->isDeleted();
});
```

## useReferralHandler

This method defines a closure that handles referrals received during the sync process. If you do not care to handle
referrals, you do not have to define this.

```php
use FreeDSx\Ldap\Sync\Result\SyncReferralResult;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;

$syncRepl->useReferralHandler(function(SyncReferralResult $result) {
    // The array of LdapUrl objects for this referral result.
    $result->getReferrals();
    // The raw result state of the referral. See "SyncStateControl::STATE_*"
    $result->getState();
    // The raw LDAP message for this referral. Can get the result code / controls / etc.
    $result->getMessage();
});
```

## useFilter

This method can be passed an object implementing the `FilterInterface`. This is the same filter that is constructed for
an LDAP search with the client. This filter is what limits the results for what is returned for the changes:

```php
use FreeDSx\Ldap\Search\Filters;

# Use the Filters factory helper to construct the LDAP filter to use.
# This filter would limit the results to just user objects.
$syncRepl->useFilter(Filters::equal('objectClass', 'user'));
```
