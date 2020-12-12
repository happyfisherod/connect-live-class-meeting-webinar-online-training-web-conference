<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\TwoFactorSecurityRequest;
use App\Repositories\Auth\TwoFactorSecurityRepository;

class TwoFactorSecurity extends Controller
{
    protected $request;
    protected $repo;

    /**
     * Instantiate a new controller instance
     * @return void
     */
    public function __construct(
        Request $request,
        TwoFactorSecurityRepository $repo
    ) {
        $this->request = $request;
        $this->repo = $repo;
    }

    /**
     * Validate two factor security
     * @post ("/api/auth/security")
     * @param ({
     *      @Parameter("email", type="email", required="true", description="User email"),
     * })
     * @return array
     */
    public function __invoke(TwoFactorSecurityRequest $request)
    {
        $this->repo->changePassword();

        return $this->success(['message' => __('global.changed', ['attribute' => __('auth.login.props.password')])]);
    }
}
