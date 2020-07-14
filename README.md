Filter module
============================

## Installing the module
You can install the module with composer:

    composer require leshik-scand/simplesamlphp-module-tokenvalidity

## Example configuration

_config/config.php_

```
   authproc.sp = array(
       ...
        10 => [
            'class' => 'tokenvalidity:Validation',
            'redirectUser' => true,
            'redirectUrl' => 'http://google.com',
            'dateInterval' => 'PT5M',
        ],
        ...
   )
```