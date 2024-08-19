<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Illuminate\Support\Facades\Mail;





Route::get('/me', [AuthController::class, 'me'])->middleware('auth:api', 'verified')->name('me');

Route::middleware(['api'])->prefix('auth')->group(function () {
    Route::post('/reverif', [AuthController::class, 'reverif'])->name('reverif');
    Route::get('/verify/{id}', [AuthController::class, 'verify'])->middleware('signed')->name('verification.verify');
    Route::post('/register', [AuthController::class, 'register'])->name('register');
    Route::post('/login', [AuthController::class, 'login'])->name('login');
    Route::post('/logout', [AuthController::class, 'logout'])->middleware('auth:api')->name('logout');
    Route::post('/refresh', [AuthController::class, 'refresh'])->middleware('auth:api')->name('refresh');
});

Route::middleware(['auth:api', 'role:ADMIN', 'verified'])->prefix('admin')->group(function(){

});

Route::middleware(['auth:api', 'role:STAFF', 'verified'])->prefix('staff')->group(function(){

});


