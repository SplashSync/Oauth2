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
use Psr\Log\LoggerInterface;
use Splash\Bundle\Models\AbstractConnector;
use Splash\Security\Oauth2\Actions;
use Splash\Security\Oauth2\Services\Oauth2ClientManager;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

/**
 * Base Class for Splash Oauth2 API Connector
 */
abstract class AbstractOauth2Connector extends AbstractConnector implements Oauth2AwareConnector
{
    public function __construct(
        private Oauth2ClientManager $oauth2ClientManager,
        EventDispatcherInterface $eventDispatcher,
        LoggerInterface $logger
    ) {
        parent::__construct($eventDispatcher, $logger);
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken() : ?AccessToken
    {
        //==============================================================================
        // Extract Access Token from Parameters
        /** @var null|array $tokenValues */
        $tokenValues = $this->getParameter(Oauth2AwareConnector::ACCESS_TOKEN);
        $tokenValues ??= array();
        //==============================================================================
        // Extract Static Token from Parameters
        $staticToken = $this->getParameter(Oauth2AwareConnector::STATIC_TOKEN);
        if ($staticToken && is_string($staticToken)) {
            $tokenValues = array_replace_recursive($tokenValues, array(
                "access_token" => $staticToken,
                "expires" => null,
            ));
        }

        return new AccessToken($tokenValues);
    }

    /**
     * {@inheritdoc}
     */
    public function getConnectedTemplate() : string
    {
        return "@SplashOauth2/Profile/connected.html.twig";
    }

    /**
     * {@inheritdoc}
     */
    public function getOfflineTemplate() : string
    {
        return "@SplashOauth2/Profile/offline.html.twig";
    }

    /**
     * {@inheritdoc}
     */
    public function getNewTemplate() : string
    {
        return "@SplashOauth2/Profile/new.html.twig";
    }

    /**
     * {@inheritdoc}
     */
    public function getMasterAction(): ?string
    {
        return Actions\Master::class;
    }

    /**
     * {@inheritdoc}
     */
    public function getSecuredActions() : array
    {
        return array(
            "connect" => Actions\Connect::class,
            "refresh" => Actions\Refresh::class,
        );
    }

    /**
     * Get Current Valid Token or Get a refreshed token
     */
    protected function getTokenOrRefresh(bool $force = false) : ?string
    {
        //==============================================================================
        // Get Current Access Token from Parameters
        $accessToken = $this->getAccessToken();
        if (!$accessToken) {
            return null;
        }
        //==============================================================================
        // Access Token is NOT Expired
        if (!$force && (empty($accessToken->getExpires()) || !$accessToken->hasExpired())) {
            return $accessToken->getToken();
        }
        //==============================================================================
        // Refresh if Possible
        if (!$this->oauth2ClientManager->refreshToken($this)) {
            return null;
        }

        return $this->getAccessToken()->getToken();
    }
}
