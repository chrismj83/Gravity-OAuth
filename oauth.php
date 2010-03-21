<?php
/**
 * Gravity OAuth class
 * 2010 ElbertF http://elbertf.com
 * http://www.gnu.org/licenses/gpl-2.0.txt GNU Public License
 */

session_start();

$gravity = new GravityOAuth;

if ( $gravity )
{
	$userInfo = $gravity->get_user_info();

	echo 'User info: <pre>', print_r($userInfo), '</pre>';
}

/*
 * Gravity OAuth
 */
class GravityOAuth
{
	private
		/*
		 * Set your client_id, client_secret and callback_url
		 */
		$clientId     = '',
		$clientSecret = '',
		$callbackURL  = '',

		$wrapVerificationCode    = '',
		$wrapVerificationCodeTTL = ''
		;
	
	public
		$auth = array()
		;

	/*
	 * Initialize
	 */
	function __construct()
	{
		/*
		 * Resume from saved session
		 */
		if ( !empty($_SESSION['auth']) )
		{
			$this->auth = unserialize($_SESSION['auth']);
		}

		/*
		 * User authorized the request
		 */
		if ( isset($_GET['wrap_verification_code']) && isset($_GET['wrap_verification_code_ttl']) )
		{
			$this->wrapVerificationCode    = $_GET['wrap_verification_code'];
			$this->wrapVerificationCodeTTL = $_GET['wrap_verification_code_ttl'];

			$this->get_tokens();
		}

		if ( $this->auth['wrapAccessToken'] )
		{
			$_SESSION['auth'] = serialize($this->auth);

			return TRUE;
		}
		else
		{
			/*
			 * Request authorization from user
			 */
			header('Location: https://api.gravity.com/beta/wrap/authorize?wrap_client_id=' . $this->clientId . '&wrap_callback=' . rawurlencode($this->callbackURL));
		}
	}

	/*
	 * Get tokens
	 */
	private function get_tokens()
	{
		$url = 'https://api.gravity.com/beta/wrap/access_token';

		if ( !function_exists('curl_init') )
		{
			die('cURL is not installed, see http://www.php.net/manual/en/book.curl.php');
		}

		$session = curl_init();

		curl_setopt($session, CURLOPT_URL,            $url);
		curl_setopt($session, CURLOPT_RETURNTRANSFER, TRUE);
		curl_setopt($session, CURLOPT_SSL_VERIFYPEER, FALSE);
		curl_setopt($session, CURLOPT_POST,           TRUE);
		curl_setopt($session, CURLOPT_POSTFIELDS,     array(
			'wrap_client_id'         => $this->clientId,
			'wrap_client_secret'     => $this->clientSecret,
			'wrap_verification_code' => $this->wrapVerificationCode,
			'wrap_callback'          => $this->callbackURL
			));

		$json = curl_exec($session);
		$info = curl_getinfo($session);

		if ( $info['http_code'] == 200 )
		{
			$r = json_decode($json);

			$this->auth = array(
				'wrapAccessToken'          => $r->wrap_access_token,
				'wrapAccessTokenExpiresIn' => $r->wrap_access_token_expires_in,
				'wrapRefreshToken'         => $r->wrap_refresh_token,
				'gravityUsername'          => $r->gravity_username,
				'gravityUserAvatar'        => $r->gravity_user_avatar
				);
		}
		else
		{
			die('Failed to get access token, HTTP code ' .  $info['http_code']);
		}

		curl_close($session);
	}

	/*
	 * Refresh access token
	 */
	private function refresh_access_token()
	{
		$url = 'https://api.gravity.com/beta/wrap/access_token';

		$session = curl_init();
					
		curl_setopt($session, CURLOPT_URL,            $url);
		curl_setopt($session, CURLOPT_RETURNTRANSFER, TRUE);
		curl_setopt($session, CURLOPT_SSL_VERIFYPEER, FALSE);
		curl_setopt($session, CURLOPT_POST,           TRUE);
		curl_setopt($session, CURLOPT_POSTFIELDS,     array(
			'wrap_client_id'     => $this->clientId,
			'wrap_refresh_token' => $this->auth['wrapRefreshToken']
			));

		$json = curl_exec($session);
		$info = curl_getinfo($session);

		if ( $info['http_code'] == 200 )
		{
			$r = json_decode($json);

			$this->auth = array(
				'wrapAccessToken'          => $r->wrap_access_token,
				'wrapAccessTokenExpiresIn' => $r->wrap_access_token_expires_in
				);
		}
		else
		{
			die('Failed to refresh access token, HTTP code ' .  $info['http_code']);
		}	
	}

	/*
	 * Get user information
	 */
	function get_user_info()
	{
		$url = 'https://api.gravity.com/beta/user/' . $this->auth['gravityUsername'] . '?wrap_access_token=' . $this->auth['wrapAccessToken'] . '&format=debug';

		$session = curl_init();

		curl_setopt($session, CURLOPT_URL,            $url);
		curl_setopt($session, CURLOPT_RETURNTRANSFER, TRUE);
		curl_setopt($session, CURLOPT_SSL_VERIFYPEER, FALSE);

		$json = curl_exec($session);
		$info = curl_getinfo($session);

		if ( $info['http_code'] == 200 )
		{
			return json_decode($json);
		}
		else
		{
			if ( $info['http_code'] == 401 )
			{
				$this->refresh_access_token();

				// Try again with the new access token
				return $this->get_user_info();
			}
			else
			{
				die('Failed to get user info, HTTP code ' .  $info['http_code']);
			}
		}

		curl_close($session);
	}
}
