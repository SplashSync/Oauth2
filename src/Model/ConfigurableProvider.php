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

use League\OAuth2\Client\Provider\AbstractProvider;
use Splash\Bundle\Models\AbstractConnector;

/**
 * Make Oauth2 Client provider Configurable
 */
abstract class ConfigurableProvider extends AbstractProvider
{
    /**
     * Connector Storage Key for Private Client ID
     */
    const CLIENT_ID = "apiKey";

    /**
     * Connector Storage Key for Private Client Secret
     */
    const CLIENT_SECRET = "apiSecret";

    /**
     * Configure Oauth2 Client for this Connector
     */
    public function configure(AbstractConnector $connector): void
    {
        $this->detectApiClient($connector);
    }

    /**
     * Detect Oauth2 Client Configuration from Connector
     */
    public function detectApiClient(AbstractConnector $connector): void
    {
        $clientId = $connector->getParameter(self::CLIENT_ID);
        $clientSecret = $connector->getParameter(self::CLIENT_SECRET);

        if ($clientId && $clientSecret && is_string($clientId) && is_string($clientSecret)) {
            $this->clientId = $clientId;
            $this->clientSecret = $clientSecret;
        }
    }
}
