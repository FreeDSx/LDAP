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

namespace Tests\Unit\FreeDSx\Ldap;

use FreeDSx\Ldap\Control\Ad\DirSyncRequestControl;
use FreeDSx\Ldap\Control\Ad\ExpectedEntryCountControl;
use FreeDSx\Ldap\Control\Ad\ExtendedDnControl;
use FreeDSx\Ldap\Control\Ad\PolicyHintsControl;
use FreeDSx\Ldap\Control\Ad\SdFlagsControl;
use FreeDSx\Ldap\Control\Ad\SetOwnerControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Control\SubentriesControl;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Control\Vlv\VlvControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\TestCase;

class ControlsTest extends TestCase
{
    public function testItShouldCreateAPagingControl(): void
    {
        $result = Controls::paging(100);
        $expected = new PagingControl(100, '');
        
        $this->assertEquals(
            $expected,
            $result
        );
    }

    public function testItShouldCreateAVlvOffsetControl(): void
    {
        $result = Controls::vlv(10, 12);
        $expected = new VlvControl(10, 12, 1, 0);
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateAVlvFilterControl(): void
    {
        $result = Controls::vlvFilter(
            10,
            12,
            Filters::gte('foo', 'bar')
        );
        $expected = new VlvControl(
            10,
            12,
            null,
            null,
            new GreaterThanOrEqualFilter('foo', 'bar')
        );
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateAnSdFlagsControl(): void
    {
        $result = Controls::sdFlags(7);
        $expected = new SdFlagsControl(7);
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateAPasswordPolicyControl(): void
    {
        $result = Controls::pwdPolicy();
        $expected = new Control(Control::OID_PWD_POLICY, true);
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateASubtreeDeleteControl(): void
    {
        $result = Controls::subtreeDelete();
        $expected = new Control(Control::OID_SUBTREE_DELETE);
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateASortingControlUsingAString(): void
    {
        $result = Controls::sort('cn');
        $expected = new SortingControl(new SortKey('cn'));
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateASortingControlUsingASortKey(): void
    {
        $result = Controls::sort(new SortKey('foo'));
        $expected = new SortingControl(new SortKey('foo'));
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateAnExtendedDnControl(): void
    {
        $result = Controls::extendedDn();
        $expected = new ExtendedDnControl();
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateADirSyncControl(): void
    {
        $result = Controls::dirSync();
        $expected = new DirSyncRequestControl();
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateADirSyncControlWithOptions(): void
    {
        $result = Controls::dirSync(
            DirSyncRequestControl::FLAG_INCREMENTAL_VALUES
            | DirSyncRequestControl::FLAG_OBJECT_SECURITY,
            'foo'
        );
        $expected = new DirSyncRequestControl(
            DirSyncRequestControl::FLAG_INCREMENTAL_VALUES
            | DirSyncRequestControl::FLAG_OBJECT_SECURITY,
            'foo'
        );
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateAnExpectedEntryCountControl(): void
    {
        $result = Controls::expectedEntryCount(1, 100);
        $expected = new ExpectedEntryCountControl(1, 100);
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateAPolicyHintsControl(): void
    {
        $result = Controls::policyHints();
        $expected = new PolicyHintsControl();
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateASetOwnersControl(): void
    {
        $result = Controls::setOwner('foo');
        $expected = new SetOwnerControl('foo');
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateAShowDeletedControl(): void
    {
        $result = Controls::showDeleted();
        $expected = new Control(Control::OID_SHOW_DELETED, true);
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateAShowRecycledControl(): void
    {
        $result = Controls::showRecycled();
        $expected = new Control(Control::OID_SHOW_RECYCLED, true);
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateASubentriesControl(): void
    {
        $result = Controls::subentries();
        $expected = new SubentriesControl(true);
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldCreateAManageDsaItControl(): void
    {
        $result = Controls::manageDsaIt();
        $expected = new Control(Control::OID_MANAGE_DSA_IT, true);
        
        $this->assertEquals($expected, $result);
    }

    public function testItShouldGetASyncRequestControl(): void
    {
        $result = Controls::syncRequest();
        $expected = new SyncRequestControl();
        
        $this->assertEquals($expected, $result);

        $result = Controls::syncRequest(
            'foo',
            SyncRequestControl::MODE_REFRESH_AND_PERSIST
        );
        $expected = new SyncRequestControl(
            SyncRequestControl::MODE_REFRESH_AND_PERSIST,
            'foo',
        );
        
        $this->assertEquals($expected, $result);
    }
}
