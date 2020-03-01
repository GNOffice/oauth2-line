<?php
/**
 * Created by IntelliJ IDEA.
 * User: usui
 * Date: 2020/02/21
 * Time: 14:51
 */

namespace GNOffice\OAuth2\Client\Provider\Exception;

use RuntimeException;
use Throwable;

class InvalidTokenException extends RuntimeException
{
    public function __construct($message = "", $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
