<?php

namespace App\Repositories\Auth;

use App\Models\User;
use App\Models\Contact;
use Illuminate\Support\Str;
use App\Enums\Auth\UserStatus;
use App\Http\Resources\AuthUser;
use App\Notifications\SendEmailOtp;
use Illuminate\Validation\ValidationException;

class LoginWithOtpRepository
{
    protected $user;
    protected $contact;

    /**
     * Instantiate a new instance
     * @return void
     */
    public function __construct(
        User $user,
        Contact $contact
    ) {
        $this->user = $user;
        $this->contact = $contact;
    }

    /**
     * Login with otp
     *
     * @return bool|array
     */
    public function login()
    {
        if (request()->has('email') && ! request()->has('otp')) {
            return $this->generateEmailOtp();
        } else if (request()->has('email') && request()->has('otp')) {
            return $this->validateEmailOtp();
        }
    }

    /**
     * Generate email otp
     */
    private function generateEmailOtp() : bool
    {
        $user = $this->user->whereEmail(request('email'))->first();

        if ($user) {
            $user->validateStatus(false); 

            $this->sendOtp($user);

            return true;
        }

        $contact = $this->contact->whereEmail(request('email'))->first();

        if (! $contact) {
            throw ValidationException::withMessages(['email' => __('auth.password.user')]);
        }

        $this->sendOtp($contact);

        return true;
    }

    /**
     * Validate email otp
     */
    private function validateEmailOtp() : array
    {
        $user = $this->user->whereEmail(request('email'))->first();

        if ($user) {
            $this->validateCache($user);

            $user->validateStatus();

            if (request('device_name')) {
                $token = $user->createToken(request('device_name'))->plainTextToken;
            } else {
                \Auth::login($user);
            }
            
            return [
                'message' => __('auth.login.logged_in'),
                'user'    => new AuthUser($user),
                'token'   => isset($token) ? $token : null
            ];
        }

        $contact = $this->contact->whereEmail(request('email'))->first();

        if (! $contact) {
            throw ValidationException::withMessages(['email' => __('auth.password.user')]);
        }

        $this->validateCache($contact);

        $user = $user->forceCreate([
            'uuid' => Str::uuid(),
            'email' => request('email'),
            'name' => $contact->name,
            'email_verified_at' => now(),
            'status' => UserStatus::ACTIVATED
        ]);

        $user->validateStatus();

        if (request('device_name')) {
            $token = $user->createToken(request('device_name'))->plainTextToken;
        } else {
            \Auth::login($user);
        }
        
        return [
            'message' => __('auth.login.logged_in'),
            'user'    => new AuthUser($user),
            'token'   => isset($token) ? $token : null
        ];
    }

    /**
     * Send otp
     *
     * @param User|Contact $model
     */
    private function sendOtp($model) : void
    {   
        $type = $model instanceof User ? 'user' : 'contact';

        $otp = rand(100000, 999999);

        (new User)->forceFill([
            'email' => $model->email,
        ])->notify(new SendEmailOtp($otp));

        cache(['otp_email_' . $type . '_'.$model->id => $otp], config('config.auth.otp_lifetime'));
    }

    /**
     * Validate cache
     *
     * @param User|Contact $model
     */
    private function validateCache($model) : void
    {
        $type = $model instanceof User ? 'user' : 'contact';

        if (! \Cache::has('otp_email_'. $type .'_'.$model->id)) {
            throw ValidationException::withMessages(['otp' => __('auth.login.invalid_otp')]);
        }

        if (\Cache::get('otp_email_'. $type .'_'.$model->id) != request('otp')) {
            throw ValidationException::withMessages(['otp' => __('auth.login.invalid_otp')]);
        }
    }
}