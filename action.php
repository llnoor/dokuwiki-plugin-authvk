<?php
/**
 * DokuWiki Plugin authvk (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Ilnur Gimazov <ubvfp94@mail.ru>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class action_plugin_authvk extends DokuWiki_Action_Plugin {

    public function register(Doku_Event_Handler $controller) {
        global $conf;
        if($conf['authtype'] != 'authvk') return;

        $conf['profileconfirm'] = false; 

		$controller->register_hook('DOKUWIKI_STARTED', 'BEFORE', $this, 'handle_start');
        $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'handle_loginform');
        $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'handle_dologin');
    }
	
	public function handle_start(Doku_Event &$event, $param) {
		global $USERINFO;
		global $conf;
		global $connection;
		global $auth;
		
		if (isset($_GET['code'])) {
			$vk_client_id = $this->getConf('client_id');
			$vk_client_secret = $this->getConf('client_secret');
			$vk_redirect_uri = $this->getConf('redirect_uri');
			$vk_admin_id = $this->getConf('admin_id');
			$vk_group_id_of_admins = $this->getConf('group_id_of_admins');
			$vk_group_id_of_moderators = $this->getConf('group_id_of_moderators');
			$vk_group_id_of_users = $this->getConf('group_id_of_users');
				
			$vk_url = 'http://oauth.vk.com/authorize';
			
			$vk_state = $_GET['state'];
			msg ($vk_state);
			if ((empty($vk_state)) or ($_SERVER['SERVER_NAME']."/start?do=login"==$vk_state))
			{$vk_state = $_SERVER['SERVER_NAME'];}
		
			$vk_result = false;
			$vk_params = array(
				'client_id' => $vk_client_id,
				'client_secret' => $vk_client_secret,
				'code' => $_GET['code'],
				'redirect_uri' => $vk_redirect_uri
			);
			
			$vk_token = json_decode(file_get_contents('https://oauth.vk.com/access_token' . '?' . htmlspecialchars_decode(urldecode(http_build_query($vk_params)))), true);
			
			if (isset($vk_token['access_token'])) {
				$vk_params = array(
					'uids'         => $vk_token['user_id'],
					'fields'       => 'uid,first_name,last_name,screen_name,sex,bdate,photo_big',
					'access_token' => $vk_token['access_token']
				);

				$vk_userInfo = json_decode(file_get_contents('https://api.vk.com/method/users.get' . '?' . htmlspecialchars_decode(urldecode(http_build_query($vk_params)) )), true);
				if (isset($vk_userInfo['response'][0]['uid'])) {
					$vk_userInfo = $vk_userInfo['response'][0];
				}
			}

			$vk_group_params = array(
					'group_id' => $vk_group_id_of_admins,
					'user_id' => $vk_userInfo['uid'],
					'extended' => '1'
				);
			
			$vk_group_id_of_admins_Info = json_decode(file_get_contents('https://api.vk.com/method/groups.isMember' . '?' . htmlspecialchars_decode(urldecode(http_build_query($vk_group_params)) )), true);
			
			$vk_group_params = array(
					'group_id' => $vk_group_id_of_moderators,
					'user_id' => $vk_userInfo['uid'],
					'extended' => '1'
				);
			
			$vk_group_id_of_moderators_Info = json_decode(file_get_contents('https://api.vk.com/method/groups.isMember' . '?' . htmlspecialchars_decode(urldecode(http_build_query($vk_group_params)) )), true);
			
			$vk_group_params = array(
					'group_id' => $vk_group_id_of_users,
					'user_id' => $vk_userInfo['uid'],
					'extended' => '1'
				);
			
			$vk_group_id_of_users_Info = json_decode(file_get_contents('https://api.vk.com/method/groups.isMember' . '?' . htmlspecialchars_decode(urldecode(http_build_query($vk_group_params)) )), true);
					
			if ($vk_group_id_of_users ==0) {
				$vk_result = true; 
			}elseif (($vk_group_id_of_users_Info['response']['member'] ==1) 
					or (($vk_group_id_of_moderators_Info['response']['member'] ==1) 
					or ($vk_group_id_of_admin_Info['response']['member'] ==1))) {
				$vk_result = true;
			}else{
				$vk_result = false;
			}
				
			
			if ($vk_result) {
				$vk_login = 'vk_'.$vk_userInfo['uid'];
				$vk_pass = 'yrefd3'.$vk_userInfo['uid'];
				$vk_fullname = $vk_userInfo['first_name'].' '.$vk_userInfo['last_name'];
				if (isset($vk_token['email'])) {
					$vk_email = $vk_token['email'];
				}else{
					$vk_email = $vk_userInfo['uid'].'@vk.com';
				}
				
				msg($vk_userInfo['uid']);
				
				if (!empty($vk_login))
				{
				if(($auth->getUserData($vk_login) == false)  and (!empty($vk_fullname)) ){
					$auth->triggerUserMod('create', array($vk_login, $vk_pass, $vk_fullname, $vk_email));
				}
							
				$sticky = true;
				$silent = true;
				$secret = auth_cookiesalt(!$sticky, true); //bind non-sticky to session
				auth_setCookie($vk_login, auth_encrypt($vk_pass, $secret), $sticky);
				
				$USERINFO['pass'] = $vk_pass;
				$USERINFO['name'] = $vk_fullname;
				$USERINFO['mail'] = $vk_email;
				
				if ($vk_group_id_of_moderators_Info['response']['member']==1) 
					$USERINFO['grps'] = array('group','user');
				if ($vk_userInfo['uid']==$vk_admin_id) 
					$USERINFO['grps'] = array('admin','user');
				if ($vk_group_id_of_admins_Info['response']['member']==1) 
					$USERINFO['grps'] = array('admin','user');
				
				$_SESSION[DOKU_COOKIE]['auth']['user'] = $vk_fullname;
				$_SESSION[DOKU_COOKIE]['auth']['mail'] = $vk_email;
				$_SESSION[DOKU_COOKIE]['auth']['pass'] = $vk_pass;
				$_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
				}
			}else{
				msg($this->getLang('vk_sorry').'<a href="https://vk.com/club' . $vk_group_id_of_users .  '">VK_group</a>');
			}
			send_redirect('http://'.$vk_state);
		}

		if (empty($_SERVER['REMOTE_USER']))
		{
			$vk_client_id = $this->getConf('client_id');
			$vk_client_secret = $this->getConf('client_secret');
			$vk_redirect_uri = $this->getConf('redirect_uri');
			$vk_url = 'http://oauth.vk.com/authorize';
			
			$params = array(
			'client_id'     => $vk_client_id,
			'redirect_uri'  => $vk_redirect_uri ,
			'response_type' => 'code',
			'scope' => 'uid,first_name,last_name,sex,bdate,domain,email,groups',
			'state' => $_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']
			);

			$url = $vk_url . '?'. htmlspecialchars_decode(urldecode(http_build_query($params))) ;
			msg("<script> setTimeout( 'location=\" ".$url ."\";', 100 ); </script>");
		}
    }
	
	public function handle_loginform(Doku_Event &$event, $param) {
        global $conf;
		
		$vk_client_id = $this->getConf('client_id');
		$vk_client_secret = $this->getConf('client_secret');
		$vk_redirect_uri = $this->getConf('redirect_uri');
		$vk_url = 'http://oauth.vk.com/authorize';
		
		$params = array(
		'client_id'     => $vk_client_id,
		'redirect_uri'  => $vk_redirect_uri ,
		'response_type' => 'code',
		'scope' => 'uid,first_name,last_name,sex,bdate,domain,email,groups',
		'state' => $_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']
		);

        $form =& $event->data;
        $html = '<p><a href="' . $vk_url . '?' . urldecode(http_build_query($params)) . '">'.$this->getLang('loginButton').'</a></p>';
		$form->_content = array();
        $form->_content[] = form_openfieldset(array('_legend' => $this->getLang('loginwith'), 'class' => 'plugin_authvk'));
        $form->_content[] = $html;
        $form->_content[] = form_closefieldset();
    }

	public function handle_dologin(Doku_Event &$event, $param) {
        global $lang;
        global $ID;
		global $conf;
		
		$vk_client_id = $this->getConf('client_id');
		$vk_client_secret = $this->getConf('client_secret');
		$vk_redirect_uri = $this->getConf('redirect_uri');
		$vk_url = 'http://oauth.vk.com/authorize';
		
		$params = array(
		'client_id'     => $vk_client_id,
		'redirect_uri'  => $vk_redirect_uri ,
		'response_type' => 'code',
		'scope' => 'uid,first_name,last_name,sex,bdate,domain,email,groups',
		'state' => $_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']
		);

        $lang['btn_login'] = $this->getLang('loginButton') ;
        if($event->data != 'login') return true;
		$url = $vk_url . '?'. htmlspecialchars_decode(urldecode(http_build_query($params)))  ;
        send_redirect($url);
    }	
}

