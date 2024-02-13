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

namespace Splash\Security\Oauth2\Services;

use Exception;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use Splash\Bundle\Models\AbstractConnector;
use Splash\Security\Oauth2\Model\ConfigurableProvider;
use Splash\Security\Oauth2\Model\Oauth2AwareConnector;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * Splash manager for Connectors Oauth2 Features
 */
class Oauth2ClientManager
{
    public function __construct(
        private ClientRegistry $registry,
        private SessionInterface $session,
    ) {
    }

    /**
     * Get Connector Connect Redirect Response
     */
    public function connect(AbstractConnector $connector): ?Response
    {
        //==============================================================================
        // Safety Check - Connector Webservice Id is Defined
        if (!$webserviceId = $connector->getWebserviceId()) {
            return null;
        }
        //==============================================================================
        // Safety Check - Get & Configure Oauth2 Client
        if (!$client = $this->getClient($connector)) {
            return null;
        }
        //==============================================================================
        // Generate Redirect Request
        $request = $client->redirect(array(), array());
        //==============================================================================
        // Store Webserver ID in Session so that we could update after authorization
        $this->session->set(
            $client->getOAuth2Provider()->getState(),
            $webserviceId
        );

        //==============================================================================
        // Do Shopify OAuth2 Authentification
        return $request;
    }

    /**
     * Save Token on Auth Redirection
     */
    public function saveToken(Request $request, AbstractConnector $connector): ?Response
    {
        //==============================================================================
        // Extract State from Request
        $code = $request->query->has("code");
        $state = $request->get("state");
        if (!$code || !$state || !is_string($state)) {
            return null;
        }

        //==============================================================================
        // Fetch Webserver ID from Session so that we could identify
        $webserverId = $this->session->get($state);
        if (!$webserverId || !is_string($webserverId)) {
            return null;
        }
        //==============================================================================
        // Safety Check - Connector Identification by Webservice Id works
        if (!$connector->identify($webserverId)) {
            return null;
        }
        //==============================================================================
        // Safety Check - Get & Configure Oauth2 Client
        if (!$client = $this->getClient($connector)) {
            return null;
        }

        try {
            //==============================================================================
            // Get Access Token
            $accessToken = $client->getAccessToken();
            //==============================================================================
            // Now update Connector Configuration
            $connector->setParameter(Oauth2AwareConnector::ACCESS_TOKEN, $accessToken->jsonSerialize());
            $connector->updateConfiguration();
        } catch (Exception $e) {
            return new Response(
                sprintf('Connexion Refused: %s', $e->getMessage()),
                Response::HTTP_UNAUTHORIZED
            );
        }

        return self::getCloseResponse();
    }

    /**
     * Refresh Current Connector Oauth2 Token
     */
    public function refreshToken(AbstractConnector $connector): ?Response
    {
        //==============================================================================
        // Safety Check - Get & Configure Oauth2 Client
        if (!$client = $this->getClient($connector)) {
            return null;
        }
        //==============================================================================
        // Safety Check - Connector has as Access Token
        if (!$accessToken = $this->getAccessToken($connector)) {
            return null;
        }
        //==============================================================================
        // Safety Check - Connector has as Access Token
        if (!$refreshToken = $accessToken->getRefreshToken()) {
            return null;
        }

        try {
            //==============================================================================
            // Get Access Token
            $accessToken = $client->refreshAccessToken($refreshToken);
            //==============================================================================
            // Now update Connector Configuration
            $connector->setParameter(Oauth2AwareConnector::ACCESS_TOKEN, $accessToken->jsonSerialize());
            $connector->updateConfiguration();
        } catch (Exception) {
            return null;
        }

        return self::getCloseResponse();
    }

    /**
     * Return Default Empty Connector Response
     */
    public static function getCloseResponse(): Response
    {
        return new Response('<script>window.close();</script>');
    }

    /**
     * Get Connector Oauth Client
     */
    private function getClient(AbstractConnector $connector): ?OAuth2ClientInterface
    {
        //==============================================================================
        // Safety Check - This Connector Uses Oauth2
        if (!($connector instanceof Oauth2AwareConnector)) {
            return null;
        }
        //==============================================================================
        // Load Connector OAuth2 Client
        $client = $this->registry->getClient($connector->getOauth2ClientCode());
        $provider = $client->getOAuth2Provider();
        //==============================================================================
        // Safety Check - Provider is Valid
        if (!($provider instanceof AbstractProvider)) {
            return null;
        }
        //==============================================================================
        // Configure Provider if Compatible
        if ($provider instanceof ConfigurableProvider) {
            $provider->configure($connector);
        }

        //==============================================================================
        // Return Configured Provider
        return $client;
    }

    /**
     * Safe Get of Connector Current Access Token
     */
    private function getAccessToken(
        AbstractConnector $connector,
    ): ?AccessToken {
        //==============================================================================
        // Safety Check - This Connector Uses Oauth2
        if (!($connector instanceof Oauth2AwareConnector)) {
            return null;
        }

        //==============================================================================
        // Get Access Token from Connector
        return $connector->getAccessToken();
    }
}
