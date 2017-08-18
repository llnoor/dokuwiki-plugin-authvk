<?php
/**
 * Russian settings translation for the authvk plugin.
 *
 * @license  GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author   Ilnur Gimazov <ubvfp94@mail.ru>
 */
 global $conf;
 
$lang['userexists']            = 'Извините, пользователь с таким логином уже существует.';
$lang['usernotexists']         = 'Этот пользователь незарегистрирован.';
$lang['writefail']             = 'Невозможно обновить данные пользователя. Свяжитесь с администратором вики';
$lang['login_button']       = 'Log in';
$lang['loginButton']   = 'Аутентификация через ВКонтакте';
$lang['vk_sorry'] = 'Извините, но вы должны состоять в <a href="https://vk.com/club' . $this->getConf('group_id_of_users') .  '">этой VK группе</a>';
