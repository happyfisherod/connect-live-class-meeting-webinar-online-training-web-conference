<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
 */

// custom test route
Route::get('/test', function () {
    return;
});

// language route
Route::get('/js/lang', function () {
    if (App::environment('local') || env('APP_MODE') === 'test') {
        Cache::forget('lang.js');
    }
    if (\Cache::has('locale')) {
        config(['app.locale' => \Cache::get('locale')]);
    }

    $strings = Cache::remember('lang.js', 86400, function () {
        $lang = config('app.locale');
        $files = glob(resource_path('lang/' . $lang . '/*.php'));
        $strings = [];

        foreach ($files as $file) {
            $name = basename($file, '.php');
            $strings[$name] = require $file;
        }
        return $strings;
    });
    header('Content-Type: text/javascript');
    echo ('window.locale = ' . json_encode($strings) . ';');
    exit();
})->name('assets.lang');

Route::get('auth/login/{provider}', 'Auth\SocialLoginController@redirectToProvider');
Route::get('auth/login/{provider}/callback', 'Auth\SocialLoginController@handleProviderCallback');

Route::group(['middleware' => ['auth:sanctum']], function () {
    Route::get('/meetings/{meeting}/downloads/{media}', 'MeetingMediaController@download');
});

// app route
Route::get('/app/{vue?}', function () {
    return view('app');
})->where('vue', '[\/\w\.-]*')->name('app');

Route::get('/', function () {
    return redirect('/app/login');
});
