<?php

namespace App;

use Ginov\CaldavPlugsUserInterface;
use App\Security\User;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class GinovJwt
{

   const ENCODER = 'HS256';
   const EXP_DELAY = 3600;

   public static function encode(string $secret, \App\Entity\User $userDto): string
   {
      // dd($userDto);
      return JWT::encode([
         'lastname' => $userDto->getLastname(),
         'firstname' => $userDto->getFirstname(),
         'email' => $userDto->getEmail(),
         'password' => $userDto->getPassword(),
         'exp' => time() + self::EXP_DELAY
      ], $secret, self::ENCODER);
   }

   /* public static function encode(string $secret, PlateformUserInterface $user): string
   {
      return JWT::encode([
         'payload' => $user->__toString(),
         'exp' => time() + self::EXP_DELAY
      ], $secret, self::ENCODER);
   } */

   public static function decode(string $jwt, string $secret)
   {
      return JWT::decode(
         $jwt,
         new Key($secret, self::ENCODER)
      );
   }
}
