<?php

namespace App\Controller;

use App\GinovJwt;
use App\Entity\User;
use Firebase\JWT\JWT;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\HttpKernel\Attribute\MapRequestPayload;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\HttpFoundation\Request;

class SecurityController extends AbstractController
{

    public function __construct(private ParameterBagInterface $parameterBag) {}

    #[Route(path: '/api/login', name: 'api_login', methods: ['POST'])]
    public function login(AuthenticationUtils $authenticationUtils): JsonResponse
    {
        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();

        // last username entered by the user
        // $lastUsername = $authenticationUtils->getLastUsername();

        $token = GinovJwt::encode($this->parameterBag->get('jwt.api.key'), $this->getUser());

        // dd($this->getUser());

        /** @var User */
        $user =  $this->getUser();
        $user->setApiToken($token);

        // return $this->json(['token' => $token, 'error' => $error]);
        return $this->json(['user' => $user, 'error' => $error], Response::HTTP_OK, [], ['groups' => 'user']);
    }

    #[Route(path: '/api/register', name: 'api_register', methods: ['POST'])]
    public function register(
        #[MapRequestPayload] User $user,
        ValidatorInterface $validator,
        UserPasswordHasherInterface $passwordHasher,
        EntityManagerInterface $em,
        Request $request
    ): JsonResponse {

        $errors = $validator->validate($user);
        $verify_password = $request->request->get('verify_password', false);

        if (!$verify_password || $verify_password !== $user->getPassword())
            return $this->json(['errors' => 'verify_password']);

        if (count($errors)) {
            return $this->json(['errors' => $errors]);
        }

        $em->persist(
            $user
                ->setPassword($passwordHasher->hashPassword(
                    $user,
                    $user->getPassword()
                ))
                ->setCreateAt(new \DateTimeImmutable())
                ->setUpdateAt(new \DateTimeImmutable())
        );

        $em->flush();

        return $this->json(['user' => $user], Response::HTTP_CREATED, ['groups' => 'user']);
    }


    // #[Route(path: '/logout', name: 'app_logout')]
    // public function logout(): void
    // {
    //     throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    // }

}
