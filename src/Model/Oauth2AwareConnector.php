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

namespace Splash\Security\Oauth2\Model;

use League\OAuth2\Client\Token\AccessToken;

/**
 * Define Interface for Oauth2 Compatible Connectors
 */
interface Oauth2AwareConnector
{
    /**
     * Connector Storage Key for Access Token
     */
    const ACCESS_TOKEN = "AccessToken";

    /**
     * Connector Storage Key for Static Token
     */
    const STATIC_TOKEN = "Token";

    /**
     * Connector Storage Key for Client Redirect Uri
     */
    const REDIRECT_URI = "apiRedirectUri";

    /**
     * Get Registration Code for Oauth2 Client
     */
    public function getOauth2ClientCode(): string;

    /**
     * Get Currently Stored Access Token
     */
    public function getAccessToken() : ?AccessToken;
}
