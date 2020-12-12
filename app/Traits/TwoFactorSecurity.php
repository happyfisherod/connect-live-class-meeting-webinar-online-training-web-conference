<?php

namespace App\Traits;

use Carbon\Carbon;
use App\Models\User;
use App\Notifications\TwoFactorSecurity as TwoFactorSecurityNotification;
use Illuminate\Validation\ValidationException;

trait TwoFactorSecurity
{
    /**
     * Set two factor security code
     * @param User $user
     */
    public function set(User $user) : void
    {
        if (! config('config.auth.two_factor_security')) {
            return;
        }

        $two_factor_code = rand(100000, 999999);

        $user->notify(new TwoFactorSecurityNotification($two_factor_code));

        cache([ 'two_factor_security_'.$user->id => Carbon::now()->toDateTimeString()], config('config.auth.two_factor_security_lifetime'));

        session()->put('2fa', true);
    }

    /**
     * Validate two factor security code
     * @param User $user
     * @param string $two_factor_code
     */
    public function validate($user, $two_factor_code) : void
    {
        if (! config('config.auth.two_factor_security')) {
            return;
        }

        if (! \Cache::has('two_factor_security_'.$user->id)) {
            throw ValidationException::withMessages(['auth.security.invalid_code']);
        }

        if (\Cache::get('two_factor_security_'.$user->id) != $two_factor_code) {
            throw ValidationException::withMessages(['auth.security.invalid_code']);
        }
    }

    /**
     * Reset two factor security code
     * @param User $user
     */
    public function reset($user) : void
    {
        \Cache::forget('two_factor_security_'.$user->id);

        session()->forget('2fa');
    }
}