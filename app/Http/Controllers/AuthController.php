<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Traits\ApiResponser;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\LoginRequest;
use Hash;

class AuthController extends Controller
{
    use ApiResponser;

    public function register(RegisterRequest $request)
    {
    

        $user = User::create([
            'name' => $request['name'],
            'password' => Hash::make($request['password']),
            'email' => $request['email']
        ]);

        return $this->success([
            'token' => $user->createToken('API Token')->plainTextToken
        ]);

    }

    public function login(LoginRequest $request)
    {
   
        $validated = $request->validated();
        
        if (!Auth::attempt($validated)) {
            return $this->error('Credentials not match', 401);
        }

        return $this->success([
            'token' => auth()->user()->createToken('API Token')->plainTextToken
        ]);
    }

    public function logout()
    {
        auth()->user()->tokens()->delete();

        return [
            'message' => 'Tokens Revoked'
        ];
    }
}