<?php

namespace SimpleSAML\Module\tokenvalidity\Auth\Process;

use \DateInterval;
use \DateTime;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Error;
use SimpleSAML\Memcache;

/**
 * Token validity filter.
 *
 * <code>
 * 10 => array(
 *     'class' => 'tokenvalidity:Validation',
 *     'redirectUser' => true,
 *     'redirectUrl' => 'http://test.com/',
 *     'dateInterval' => 'PT5M'
 * ),
 * </code>
 *
 * @package SimpleSAMLphp
 */
class Validation extends ProcessingFilter
{
    /** @var DateInterval */
    private $dateInterval;

    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);

        assert(is_array($config));

        if (array_key_exists('dateInterval', $config)) {
            $this->dateInterval = new DateInterval($config['dateInterval']);
        }
    }

    public function process(&$request)
    {
        assert(is_array($request));
        assert(array_key_exists('saml:sp:State', $request));
        assert(array_key_exists('Attributes', $request));
        $spState = $request['saml:sp:State'];
        $attributes = $request['Attributes'];

        $createTimestamp = $spState['saml:AuthnInstant'];
        $userEmail = $attributes['email'][0];
        $userHash = md5($userEmail . $createTimestamp);

        $expireTime = (new DateTime())->setTimestamp($createTimestamp)->add($this->dateInterval);
        $isUsed = (bool)Memcache::get($userHash);
        if ($isUsed) {
            throw new Error\Exception("Assertion used by user.");
        } else {
            Memcache::set($userHash, true);
        }

        if ($expireTime < (new DateTime())) {
            throw new Error\Exception("Validation period has expired.");
        }
    }
}
