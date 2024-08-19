<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Symfony\Component\HttpFoundation\Response;

class CheckRole
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */

        public function handle(Request $request, Closure $next, $role)
        {
            $user = JWTAuth::parseToken()->authenticate();

            if (!$user || $user->role !== $role) {
                return response()->json(['error' => 'Forbidden'], 403);
            }

            return $next($request);
        }
}
