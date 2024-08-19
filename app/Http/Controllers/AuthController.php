<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\ReverifRequest;
use App\Http\Resources\UsersResources;
use App\Models\User;
use Illuminate\Auth\Events\Verified;
use Illuminate\Auth\Listeners\SendEmailVerificationNotification;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Request;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{

    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(RegisterRequest $request)
    {
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);
        $user->SendEmailVerificationNotification();

        return response()->json(["message" => "Register successfully. Please verify your email"], 201);
    }


    public function verify(Request $request, $id, $hash)
    {
        $user = User::findOrFail($id);
        if ($user->hasVerifiedEmail()) {
            return response()->json([
                'status' => 'Your email address is already verified.'
            ], 201);
        }
        if ($user->markEmailAsVerified()) {
            event(new Verified($user));
        }
        return response()->json([
            'status' => 'Your email address has been verified.'
        ], 201);
    }

    public function reverif(ReverifRequest $request)
    {
        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return response()->json(['error' => 'User not found.'], 404);
        }

        if ($user->hasVerifiedEmail()) {
            return response()->json([
                'status' => 'Your email address is already verified.'
            ], 200);
        }

        // Mengirim ulang email verifikasi
        $user->sendEmailVerificationNotification();

        return response()->json([
            'status' => 'Verification email resent.'
        ], 200);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(LoginRequest $request)
    {
        $credentials =$request->only('email','password');

        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'Invalid email or password.'], 401);
        }

        $user = JWTAuth::user();

        if ($user->email_verified_at === null) {
            return response()->json(['error' => 'Email address not verified.'], 403);
        }


        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
         try {
            $user = JWTAuth::parseToken()->authenticate();

            return response()->json(UsersResources::make($user), 201);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());

            return response()->json(['message' => 'Successfully logged out']);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Logout failed'], 500);
        }
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        try {
            $token = JWTAuth::parseToken()->refresh();

            return $this->respondWithToken($token);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Token refresh failed'], 401);
        }
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        $ttl = config('jwt.ttl');

        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => $ttl
        ]);
    }
}
