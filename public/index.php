<?php
date_default_timezone_set('Asia/Novosibirsk');

use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;

require '../vendor/autoload.php';

class Cookie
{
    public function deleteCookie(Response $response, $key)
    {
        $cookie =
            urlencode($key) . 
            '=' . 
            urlencode('deleted') . 
            '; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/; secure; httponly';
        $response = $response->withAddedHeader('Set-Cookie', $cookie);

        return $response;
    }
    
    public function addCookie(Response $response, $cookieName, $cookieValue, $expiration)
    {
        $expiry = new \DateTimeImmutable('now + ' . $expiration . ' minutes');
        $cookie =
            urlencode($cookieName) . 
            '=' . 
            urlencode($cookieValue) . 
            '; expires=' . 
            $expiry->format(\DateTime::COOKIE) . 
            '; Max-Age=' .
            $expiration * 60 .
            '; path=/; secure; httponly';
        $response = $response->withAddedHeader('Set-Cookie', $cookie);

        return $response;
    }

    public function getCookieValue(Request $request, $cookieName)
    {
        $cookies = $request->getCookieParams();
        return isset($cookies[$cookieName]) ? $cookies[$cookieName] : null;
    }
}

class Auth 
{
    private $container;

    public function __construct($c)
    {
        $this->container = $c;
    }

    public function __invoke($request, $response, $next)
    {
        // проверяем наличие сохраненной cookies
        $id_user = $this->container->cookie->getCookieValue($request, 'id');
        $token = $this->container->cookie->getCookieValue($request, 'token');

        if ($id_user && $token) {
            // проверим токен
            // узнаем по id пользователя хэш пароля
            $ip = $request->getServerParam('REMOTE_ADDR');

            // заглушка
            $hash_pass = $this->container->cookie->getCookieValue($request, 'hash_pass');

            if (password_verify($ip . $hash_pass, $token)) {
                $response = $this->container->cookie->addCookie($response, 'id', $id_user, '10');
                $response = $this->container->cookie->addCookie($response, 'token', $token, '10');
                $this->container->session->auth = $id_user;
            } else {
                $this->container->session->delete('auth');
                // todo
                // удалить cookies
            }
        }

        if ($this->isAuthorized()) {
            $response = $next($request, $response);

            return $response;
        }

        return $response->withRedirect('/login');
    }

    public function isAuthorized()
    {
        return (int)$this->container->session->auth === 1;
    }

    /*
     * id_user
     * hash_pass хэш пароля пользователя (из базы)
     */
    public function login($id_user, $hash_pass)
    {
    }
}

$app = new \Slim\App();

$container = $app->getContainer();

$app->add(
    new \Slim\Middleware\Session([
        'autorefresh' => true,
        'lifetime' => '2 minutes',
    ])
);

$container['session'] = function() {

    return new \SlimSession\Helper();
};

$container['cookie'] = function() {
    return new \Cookie;
};

$app->group('', function () {
    $this->get('/', function (Request $req, Response $res) {
        $pass = password_hash("123456", PASSWORD_DEFAULT);

        $token = password_hash("192.168.30.1" . $pass, PASSWORD_DEFAULT);

        if (password_verify("192.168.30.1" . $pass, $token)) {
            echo "pass ok";
        } else {
            echo "pass not";
        }

        echo <<<HTML
    <h2>main page</h2>
    <a href="/logout">выход</a>
HTML;

    });

    $this->get('/logout', function (Request $req, Response $res) {
        $this->session->delete('auth');

        $res = $this->cookie->deleteCookie($res, 'id');
        $res = $this->cookie->deleteCookie($res, 'token');

        return $res->withRedirect('/login');
    });

})->add(new Auth($container));

$app->get('/login', function () {
    echo "<h2>login</h2>";

    echo <<<HTML
<form method="post" action="/login">
логин:
<input type="text" name="login">
pass:
<input type="text" name="pass">
запомнить:
<input type="checkbox" name="remember" value="1">
<input type="submit" name="submit">
</form>
HTML;

});

$app->post('/login', function (Request $req, Response $res) {
    $data = $req->getParsedBody();
    $login = $data['login'];
    $pass = $data['pass'];

    if ($login == $pass) {
        
        $id_user = 1;
        $this->session->auth = $id_user;

        $remember = (bool)$data['remember'];
        
        if ($remember) {
            $ip = $req->getServerParam('REMOTE_ADDR');
            $hash_pass = password_hash("123456", PASSWORD_DEFAULT);
            $token = password_hash($ip . $hash_pass, PASSWORD_DEFAULT);

            $res = $this->cookie->addCookie($res, 'id', $id_user, '10');
            $res = $this->cookie->addCookie($res, 'token', $token, '10');

            // заглушка
            $res = $this->cookie->addCookie($res, 'hash_pass', $hash_pass, '10');
        }

        return $res->withRedirect('/');
    }

    return $res->withRedirect('/login');
});

$app->run();

