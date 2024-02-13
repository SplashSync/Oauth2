<?php

/*
 *  This file is part of SplashSync Project.
 *
 *  Copyright (C) Splash Sync  <www.splashsync.com>
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  For the full copyright and license information, please view the LICENSE
 *  file that was distributed with this source code.
 */

namespace Splash\Security\Oauth2\Actions;

use Splash\Bundle\Models\AbstractConnector;
use Splash\Bundle\Models\Local\ActionsTrait;
use Splash\Security\Oauth2\Services\Oauth2ClientManager;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;

/**
 * Splash Connector Actions - Oauth2 Token Revoke
 */
class Revoke extends AbstractController
{
    use ActionsTrait;

    public function __invoke(
        Oauth2ClientManager $manager,
        AbstractConnector $connector
    ): Response {
        //==============================================================================
        // Delete Current OAuth2 Token
        return $manager->revokeToken($connector);
    }
}
