<?php

namespace App\Console\Commands;

use App\Helpers\ArrHelper;
use App\Models\Config\Role;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Illuminate\Console\Command;
use App\Models\Config\Permission;

class RefreshPermission extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'refresh:permission';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Refresh permission';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        \Artisan::call('cache:clear');

        \DB::statement('SET FOREIGN_KEY_CHECKS=0;');
        \DB::table('role_has_permissions')->truncate();
        \DB::table('permissions')->truncate();
        \DB::statement('SET FOREIGN_KEY_CHECKS=1;');

        $acl = ArrHelper::getVar('acl');

        $permissions = array();
        foreach (Arr::get($acl, 'permissions', []) as $permission_group) {
            foreach ($permission_group as $name => $permission) {
                $permissions[] = array(
                    'name' => $name,
                    'uuid' => Str::uuid(),
                    'guard_name' => 'web',
                    'created_at' => now(),
                    'updated_at' => now(),
                );
            }
        }
        Permission::insert($permissions);

        $roles = Role::all();
        $permissions = Permission::all();
        $admin_role = $roles->firstWhere('name', 'admin');

        $role_permission = array();
        foreach ($permissions as $permission) {
            $role_permission[] = array(
                'permission_id' => $permission->id,
                'role_id' => $admin_role->id,
            );
        }

        foreach (Arr::get($acl, 'permissions', []) as $permission_group) {
            foreach ($permission_group as $name => $assigned_roles) {
                foreach ($assigned_roles as $role) {
                    $role_permission[] = array(
                        'permission_id' => $permissions->firstWhere('name', $name)->id,
                        'role_id' => $roles->firstWhere('name', $role)->id
                    );
                }
            }
        }

        \DB::table('role_has_permissions')->insert($role_permission);
    }
}
