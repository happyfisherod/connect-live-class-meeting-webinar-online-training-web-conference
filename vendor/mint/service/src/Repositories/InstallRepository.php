<?php
namespace Mint\Service\Repositories;

ini_set('max_execution_time', 0);

use App\Models\User;
use App\Traits\Install;
use App\Helpers\SysHelper;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Http;
use App\Models\Config\Role as RoleModel;
use Illuminate\Validation\ValidationException;
use App\Models\Config\Permission as PermissionModel;

class InstallRepository
{
    use Install;

    /**
     * Instantiate a new controller instance.
     *
     * @return void
     */
    public function __construct(
    ) {
    }

    /**
     * Force migrate
     */
    public function forceMigrate() : string
    {
        if (SysHelper::getApp('INSTALLED')) {
            return 'Could not migrate!';
        }

        \Artisan::call('migrate', ['--force' => true]);
        
        return 'Migration completed!';
    }

    /**
     * Check all pre-requisite for script
     */
    public function getPreRequisite() : array
    {
        $pre_requisite = $this->installPreRequisite();
        $app = array(
            'verifier' => config('app.verifier'),
            'name'     => config('app.name'),
            'version'  => SysHelper::getApp('VERSION')
        );

        return compact('pre_requisite', 'app');
    }

    /**
     * Validate database connection, table count
     */
    public function validateDatabase() : bool
    {
        $link = @mysqli_connect(
            request('db_host'), 
            request('db_username'), 
            request('db_password'), 
            request('db_database'), 
            request('db_port')
        );

        if (! $link) {
            throw ValidationException::withMessages(['message' => trans('setup.install.could_not_establish_db_connection')]);
        }

        if (request('db_imported')) {
            $migrations = array();
            foreach (\File::allFiles(base_path('/database/migrations')) as $file) {
                $migrations[] = basename($file, '.php');
            }
            $db_migrations = \DB::table('migrations')->get()->pluck('migration')->all();

            if (array_diff($migrations, $db_migrations)) {
                throw ValidationException::withMessages(['message' => trans('setup.install.db_import_mismatch')]);
            }
        } else {
            $count_table_query = mysqli_query($link, "show tables");
            $count_table = mysqli_num_rows($count_table_query);

            if ($count_table) {
                throw ValidationException::withMessages(['message' => trans('setup.install.table_exist_in_database')]);
            }
        }

        return true;
    }

    /**
     * Install the script
     */
    public function install() : void
    {
        $url = config('app.verifier').'/api/cc?a=install&u='.url()->current().'&ac='.request('access_code').'&i='.config('app.item').'&e='.request('envato_email');

        $response = Http::get($url);

        if (! Arr::get($response, 'status')) {
            throw ValidationException::withMessages(['message' => Arr::get($response, 'message')]);
        }

        $checksum = Arr::get($response, 'checksum');

        $this->setDBEnv();

        $this->migrateDB();
        
        $this->populateRole();

        $this->populatePermission();

        $this->assignPermission();

        $this->makeAdmin();

        SysHelper::setApp(['INSTALLED' => $checksum]);
        SysHelper::setApp(['ACCESS_CODE' => request('access_code')]);
        SysHelper::setApp(['EMAIL' => request('envato_email')]);
        SysHelper::setEnv(['APP_ENV' => 'production']);

        if (\File::exists(public_path('storage'))) {
            \File::deleteDirectory(public_path('storage'));
        }

        \Artisan::call('storage:link');
    }

    /**
     * Write to env file
     */
    private function setDBEnv() : void
    {
        SysHelper::setEnv([
            'APP_URL'     => 'http://'.$_SERVER['HTTP_HOST'],
            'DB_PORT'     => request('db_port'),
            'DB_HOST'     => request('db_host'),
            'DB_DATABASE' => request('db_database'),
            'DB_USERNAME' => request('db_username'),
            'DB_PASSWORD' => request('db_password')
        ]);

        config(['app.env' => 'local']);
        config(['telescope.enabled' => false]);

        \DB::purge('mysql');

        config([
            'database.connections.mysql.host' => request('db_host'),
            'database.connections.mysql.port' => request('db_port'),
            'database.connections.mysql.database' => request('db_database'),
            'database.connections.mysql.username' => request('db_username'),
            'database.connections.mysql.password' => request('db_password')
        ]);

        \DB::reconnect('mysql');
    }

    /**
     * Mirage tables to database
     */
    private function migrateDB() : void
    {
        if (! request('db_imported')) {
            \Artisan::call('migrate', ['--force' => true]);
        }
        
        \Artisan::call('key:generate', ['--force' => true]);
    }

    /**
     * Populate default roles
     */
    private function populateRole() : void
    {
        $roles = array();
        foreach (config('default.roles') as $role) {
            $roles[] = array(
                'uuid' => Str::uuid(),
                'name' => $role,
                'guard_name' => 'web',
                'created_at' => now(),
                'updated_at' => now(),
            );
        }

        RoleModel::insert($roles);
    }

    /**
     * Populate default permissions
     */
    private function populatePermission() : void
    {
        $permissions = array();
        foreach (config('default.permissions') as $permission_group) {
            foreach ($permission_group as $name => $permission) {
                $permissions[] = array(
                    'uuid' => Str::uuid(),
                    'name' => $name,
                    'guard_name' => 'web',
                    'created_at' => now(),
                    'updated_at' => now(),
                );
            }
        }

        PermissionModel::insert($permissions);
    }

    /**
     * Assign default permission to default roles
     */
    private function assignPermission() : void
    {
        $roles = RoleModel::all();
        $permissions = PermissionModel::all();
        $admin_role = $roles->firstWhere('name', 'admin');

        $role_permission = array();
        foreach ($permissions as $permission) {
            $role_permission[] = array(
                'permission_id' => $permission->id,
                'role_id' => $admin_role->id,
            );
        }

        foreach (config('default.permissions') as $permission_group) {
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

    /**
     * Insert default admin details
     */
    private function makeAdmin() : void
    {
        $user = new User;
        $user->email = request('email');
        $user->name = request('name');
        $user->username = request('username');
        $user->uuid = Str::uuid();
        $user->password = bcrypt(request('password', 'password'));
        $user->status = 'activated';
        $user->email_verified_at = now();
        $user->save();

        $user->assignRole('admin');
    }
}
