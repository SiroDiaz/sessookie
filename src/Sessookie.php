<?php namespace Sessookie;

class Sessookie {

	/**
	 * the secure key(password) to encrypt and
	 * decrypt the cookie
	 */

	protected $key;

	/**
	 * The sufix used to the system know what cookie/s
	 * is/are encrypted for then do reverse work
	 */

	protected $sufix;

	protected $sessionKey;

	protected $secureSessionName;

	/**
	 * setup the configuration
	 */

	public function __construct($key = '', $sufix = 'e_', $ssname = 'sk') {
		if ($key == '' || empty($key)) {
			$this->key = null;
		}

		if($sufix == '' || empty($sufix)) {
			$this->sufix = 'e_';
		}

		$this->key = $key;
		$this->sufix = $sufix;
		$this->secureSessionName = ($this->setSecureSessionName($ssname)) ? $ssname : 'sk';
		$this->sessionKey = $this->generateSessionKey();
	}

	/**
	 * check if a cookie or cookie session exists
	 *
	 * @param string $name the session or cookie name
	 * @param string $type 's' for session or 'c' for cookie
	 */

	public function exists($name, $type) {
		
		if(empty($name)){
			return false;
		}

		if (strtolower($type) == 's') {
			return (isset($_SESSION[$name])) ? true : false;
		} elseif (strtolower($type) == 'c') {
			return (isset($_COOKIE[$name])) ? true : false;
		} else {
			return false;
		}
	}

	/**
	 * set the secure session name to another value
	 * to avoid conficts
	 *
	 * @param string $name The secure session name
	 * @return bool  false if the name is empty
	 */

	private function setSecureSessionName($name) {
		if(empty($name)) return false;

		$this->secureSessionName = $name;
	}

	public function getSecureSessionName() {
		return $this->secureSessionName;
	}

	/**
	 * return the cookie value
	 *
	 * @return mixed false if the cookie doesn't exist else other value
	 */

	public function getCookie($name) {
		if(strtolower(substr($name, 0, 2)) != 'e_'){
			return ($this->exists($name, 'c')) ? $_COOKIE[$name] : false;
		}

		return ($this->exists($name, 'c')) ? $this->decryptCookie($_COOKIE[$name]) : false; 
	}

	/**
	 * return the session value
	 *
	 * @return mixed false if the cookie session doesn't exist else other value
	 */

	public function getSession($name) {
		return ($this->exists($name, 's')) ? $_SESSION[$name] : false;
	}

	/**
	 * encrypt the cookie value(only can be seen in the server side)
	 *
	 * @param mixed $val The cookie value to encrypt with AES
	 * @return string The encrypted data
	 */

	private function encryptCookie($val) {
	
		$td = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', MCRYPT_MODE_CBC, '');
		$iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_DEV_URANDOM );
		
		mcrypt_generic_init($td, $this->key, $iv);
		$encryptedDataBin = mcrypt_generic($td, $val);
		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);
		$encryptedDataHex = bin2hex($iv).bin2hex($encryptedDataBin);
		
		return $encryptedDataHex;
	}

	/**
	 * decrypt the cookie value(only can be seen in the server side)
	 * 
	 */

	private function decryptCookie($encryptedDataHex) {
	
		$td = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', MCRYPT_MODE_CBC, '');
		$ivSizeHex = mcrypt_enc_get_iv_size($td) * 2;
		$iv = pack("H*", substr($encryptedDataHex, 0, $ivSizeHex));
		$encryptedDataBin = pack("H*", substr($encryptedDataHex, $ivSizeHex));
		
		mcrypt_generic_init($td, $this->key, $iv);
		$decrypted = mdecrypt_generic($td, $encryptedDataBin);
		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);
		
		return $decrypted;
	}

	private function generateSessionKey() {
		if(isset($_SESSION[$this->secureSessionName])) return false;

		$_SESSION[$this->secureSessionName] = str_shuffle(uniqid(microtime(true)));
	}

	/**
	 * Convert the time given in different units
	 * s --> seconds
	 * m --> minutes
	 * h --> hours
	 * d --> days
	 *
	 * @param mixed $time The duration time to convert into seconds
	 * @return int 	Returns 0 if $time is invalid else return the timestamp 
	 */

	private function convertTime($time) {

		if (is_string($time) && count(explode(' ', $time)) == 2) {

			$cases = array('s', 'm', 'h', 'd');
			list($quantity, $units) = explode(' ', $time);
			
			if(in_array(strtolower($units), $cases)) {
				
				switch(strtolower($units)) {
					case 's': return ceil(time() + $quantity);
					case 'm': return ceil(time() + $quantity * 60);
					case 'h': return ceil(time() + $quantity * 60 * 60);
					case 'd': return ceil(time() + $quantity * 60 * 60 * 24);
					default:  return 0;
				}
			} else {
				return 0;
			}
		} elseif (is_int($time)) {
			if($time >= 0){
				return time() + $time;
			}
		}
	}

	/**
	 * Create a new cookie
	 *
	 * @param string  $name     The cookie key name
	 * @param mixed   $value    The cookie value
	 * @param integer $time  	The cookie life time
	 * @param string  $path     The access (default '/') for full domain
	 * @param string  $domain   The domain name that has access to the cookie
	 * @param bool    $secure   If it's accessed only by https connection(default http)
	 * @param bool    $httpOnly If the cookie is accesible in the frontend side
	 *
	 * @return bool   false if is not created or the cookie is invalid else return true
	 */

	public function createCookie($name, $value, $time = 0, $path = '/', $domain = false, $secure = false, $httpOnly = true) {
		
		if(empty($name)) return false;

		if($time === null) return false;

		if($path === null || $domain === null) return false;

		if(!empty($this->key) && $this->key !== null && strtolower(substr($name, 0, strlen($this->sufix))) == $this->sufix){
			$value = $this->encryptCookie($value);
		}
		
		$cookie = setcookie($name, $value, $this->convertTime($time), $path, $domain, $secure, $httpOnly);

		if($cookie) {
			$_COOKIE[$name] = $value;
			return true;
		}

		return false;
	}

	/**
	 * create a new session or update an existing session
	 *
	 * @param string $name  The session name
	 * @param mixed  $value The value to assign to the session cookie
	 * @param bool   $force To modify or not if the session exists (default true)
	 * @param bool
	 */

	public function createSession($name, $value, $force = true) {
		
		if($this->exists($name, 's') && $force === false) {
			return false;
		} elseif (($this->exists($name, 's') && $force) || !$this->exists($name, 's')) {
			$_SESSION[$name] = $value;
			return true;
		}
	
	}

	/**
	 * delete a cookie
	 *
	 * @param string $name the cookie name
	 * @return bool true if the cookie was deleted else false
	 */

	public function deleteCookie($name) {
		if(!$this->exists($name, 'c')) {
			return false;
		}
		
		unset($_COOKIE[$name]);
		setcookie($name, null, -1);
		return true;
	}

	/**
	 * delete all cookies
	 *
	 * @return bool true if all cookies were deleted else false
	 */

	public function deleteAllCookies() {
		$len = count(array_keys($_COOKIE));
		$names = array_keys($_COOKIE);
		
		if(!$len) {
			foreach($_COOKIE as $key => &$val) {
				$this->deleteCookie($key);
			}
			
			/*
			for($i = $len - 1; $i >= 0; $i--) {
				$this->deleteCookie($_COOKIE[$names[$i]]);
			}
			*/
		}
	}

	/**
	 * delete a session cookie
	 *
	 * @param string $name The session cookie name
	 * @return 
	 */

	public function deleteSession($name) {
		if(!$this->exists($name, 's')) {
			return false;
		}

		$_SESSION[$name] = null;
		unset($_SESSION[$name]);
		return true;
	}

	/**
	 * delete all session cookies and clean the
	 * global variable
	 *
	 * @return bool false if there is no sessions or
	 * 			true if the sessions were remove successfuly
	 */

	public function deleteAllSessions() {
		if(!count($_SESSION)) {
			return false;
		}

		foreach ($_SESSION as $key => &$val) {
			$this->deleteSession($key);
		}
	}

	/**
	 * show all information about cookies
	 */

	public function depureCookie() {
		var_dump($_COOKIE);
	}

	/**
	 * show all information about session cookies
	 */

	public function depureSession() {
		var_dump($_SESSION);
	}

}
