<?php
/*
Unifi PHP API
- this Unifi API client comes bundled with the Unifi API Browser tool and is based on the work done by
  the following developers:
    domwo: http://community.ubnt.com/t5/UniFi-Wireless/little-php-class-for-unifi-api/m-p/603051
    fbagnol: https://github.com/fbagnol/class.unifi.php
  and the API as published by Ubiquiti:
    https://dl.ubnt.com/unifi/4.7.6/unifi_sh_api
    
------------------------------------------------------------------------------------

The MIT License (MIT)

Copyright (c) 2016, Slooffmaster

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/
define('API_CLASS_VERSION', '1.0.3');

class unifiapi {
   public $user         = "";  //not needed here when used with voucher printing script
   public $password     = "";  //not needed here when used with voucher printing script
   public $site         = "";  //not needed here when used with voucher printing script
   public $baseurl      = "";  //not needed here when used with voucher printing script
   public $controller   = "";  //not needed here when used with voucher printing script
   public $is_loggedin  = false;
   private $cookies     = "/tmp/unify";
   public $debug        = false;

   function __construct($user = "",$password = "",$baseurl = "",$site = "",$controller = "") {
      if (!empty($user)) $this->user                = $user;
      if (!empty($password)) $this->password        = $password;
      if (!empty($baseurl)) $this->baseurl          = $baseurl;
      if (!empty($site)) $this->site                = $site;
      if (!empty($controller)) $this->controller    = $controller;
      if (strpos($controller,".")) {
         $con_ver       = explode(".",$controller);
         $controller    = $con_ver[0];
      }
      $this->controller = $controller;
   }

   function __destruct() {
      if ($this->is_loggedin) {
         $this->logout();
      }
   }

   /*
   Login to Unifi Controller
   */
   public function login() {
      $this->cookies    = "";
      $ch               = $this->get_curl_obj();
      curl_setopt($ch, CURLOPT_HEADER, 1);
      if ($this->controller >= 4) {
         //Controller 4
         curl_setopt($ch, CURLOPT_REFERER, $this->baseurl."/login");
         curl_setopt($ch, CURLOPT_URL, $this->baseurl."/api/login");
         curl_setopt($ch, CURLOPT_POSTFIELDS,json_encode(array("username" => $this->user, "password" => $this->password)).":");
      } else {
         //Controller 3
         curl_setopt($ch, CURLOPT_URL, $this->baseurl."/login");
         curl_setopt($ch, CURLOPT_POSTFIELDS,"login=login&username=".$this->user."&password=".$this->password);
      }
      if ($this->debug === true) {
         curl_setopt($ch, CURLOPT_VERBOSE, TRUE);
      }
      $content=curl_exec($ch);
      if ($this->debug === true) {
         print "<pre>";
         print "\n\n-----LOGIN-------------------\n\n";
         print_r (curl_getinfo($ch));
         print "\n\n-----RESPONSE----------------\n\n";
         print $content;
         print "\n\n-----------------------------\n\n";
         print "</pre>";
      }

      $header_size  = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
      $body         = trim(substr($content, $header_size));
      $code         = curl_getinfo($ch,CURLINFO_HTTP_CODE);
      if (curl_exec($ch) === false) {
         error_log('curl error: ' . curl_error($ch));
      }
      curl_close ($ch);

      preg_match_all('|Set-Cookie: (.*);|U', substr($content, 0, $header_size), $results);
      if (isset($results[1])) {
         $this->cookies = implode(';', $results[1]);
         if (!empty($body)) {
            if (($code >= 200) && ($code < 400)) {
               if (strpos($this->cookies,"unifises") !== FALSE) {
                  $this->is_loggedin = true;
               }
            }
            if ($code === 400) {
                error_log('we have received an HTTP response status: 400. Probably a controller login failure');
                return $code;
            }
         }
      }
      return $this->is_loggedin;
   }

   /*
   Logout from Unifi Controller
   */
   public function logout() {
      if (!$this->is_loggedin) return false;
      $content            = $this->exec_curl($this->baseurl.'/logout');
      $this->is_loggedin  = false;
      $this->cookies      = '';
      return true;
   }

   /*
   Authorize a MAC address
   required parameter <mac> = client MAC address
   required parameter <minutes> = minutes (from now) until authorization expires
   optional parameter <up> = upload speed limit in kbps
   optional parameter <down> = download speed limit in kbps
   optional parameter <MBytes> = data transfer limit in MB
   optional parameter <ap_mac> = AP MAC address to which client is connected, should result in faster authorization
   return true on success
   */
   public function authorize_guest($mac,$minutes,$up=0,$down=0,$bytes=0) {
      if (!$this->is_loggedin) return false;
      $json = array('cmd' => 'authorize-guest', 'mac' => $mac, 'minutes' => $minutes);
      if ($up > 0) {
         $json += array('up'=>$up);
      }
      if ($down > 0) {
         $json += array('down'=>$down);
      }
      if ($bytes > 0) {
         $json += array('bytes'=>$bytes);
      }
      $mac              = strtolower($mac);
      $return           = false;
      $json             = json_encode($json);
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/cmd/stamgr","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            $return = true;
         }
      }
      return $return;
   }

   /*
   unauthorize a MAC address
   required parameter <MAC address>
   return true on success
   */
   public function unauthorize_guest($mac) {
      if (!$this->is_loggedin) return false;
      $return           = false;
      $mac              = strtolower($mac);
      $json             = json_encode(array('cmd' => 'unauthorize-guest', 'mac' => $mac));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/cmd/stamgr","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            $return = true;
         }
      }
      return $return;
   }

   /*
   reconnect a client
   parameter <MAC address>
   return true on success
   */
   public function reconnect_sta($mac) {
      if (!$this->is_loggedin) return false;
      $return           = false;
      $mac              = strtolower($mac);
      $json             = json_encode(array('cmd' => 'kick-sta', 'mac' => $mac));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/cmd/stamgr","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            $return = true;
         }
      }
      return $return;
   }

   /*
   block a client
   required parameter <mac> = client MAC address
   return true on success
   */
   public function block_sta($mac) {
      if (!$this->is_loggedin) return false;
      $return           = false;
      $mac              = strtolower($mac);
      $json             = json_encode(array('cmd' => 'block-sta', 'mac' => $mac));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/cmd/stamgr","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            $return = true;
         }
      }
      return $return;
   }

   /*
   unblock a client
   required parameter <mac> = client MAC address
   return true on success
   */
   public function unblock_sta($mac) {
      if (!$this->is_loggedin) return false;
      $return           = false;
      $mac              = strtolower($mac);
      $json             = json_encode(array('cmd' => 'unblock-sta', 'mac' => $mac));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/cmd/stamgr","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            $return = true;
         }
      }
      return $return;
   }

   /*
   daily stats method
   optional parameter <start> = Unix timestamp in seconds
   optional parameter <end> = Unix timestamp in seconds
   returns an array of daily stats objects
   NOTES:
   - defaults to the past 52*7*24 hours
   - "bytes" are no longer returned with controller version 4.9.1 and later
   */
   public function stat_daily_site($start = NULL, $end = NULL) {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $end              = is_null($end) ? ((time()-(time() % 3600))*1000) : $end;
      $start            = is_null($start) ? $end-(52*7*24*3600*1000) : $start;
      $json             = json_encode(array('attrs' => array('bytes', 'wan-tx_bytes', 'wan-rx_bytes', 'wlan_bytes', 'num_sta', 'lan-num_sta', 'wlan-num_sta', 'time'), 'start' => $start, 'end' => $end));
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/stat/report/daily.site','json='.$json));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $test) {
                  $return[]= $test;
               }
            }
         }
      }
      return $return;
   }

   /*
   hourly stats method for a site
   optional parameter <start> = Unix timestamp in seconds
   optional parameter <end> = Unix timestamp in seconds
   returns an array of hourly stats objects
   NOTES:
   - defaults to the past 7*24 hours
   - "bytes" are no longer returned with controller version 4.9.1 and later
   */
   public function stat_hourly_site($start = NULL, $end = NULL) {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $end              = is_null($end) ? ((time())*1000) : $end;
      $start            = is_null($start) ? $end-(7*24*3600*1000) : $start;
      $json             = json_encode(array('attrs' => array('bytes', 'wan-tx_bytes', 'wan-rx_bytes', 'wlan_bytes', 'num_sta', 'lan-num_sta', 'wlan-num_sta', 'time'), 'start' => $start, 'end' => $end));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/stat/report/hourly.site","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $test) {
                  $return[]= $test;
               }
            }
         }
      }
      return $return;
   }

   /*
   hourly stats method for all access points
   optional parameter <start> = Unix timestamp in seconds
   optional parameter <end> = Unix timestamp in seconds
   returns an array of hourly stats objects
   NOTES:
   - defaults to the past 7*24 hours
   - Unifi controller does not keep these stats longer than 5 hours with versions < 4.6.6
   */
   public function stat_hourly_aps($start = NULL, $end = NULL) {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $end              = is_null($end) ? ((time())*1000) : $end;
      $start            = is_null($start) ? $end-(7*24*3600*1000) : $start;
      $json             = json_encode(array('attrs' => array('bytes', 'num_sta', 'time'), 'start' => $start, 'end' => $end));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/stat/report/hourly.ap","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $test) {
                  $return[]= $test;
               }
            }
         }
      }
      return $return;
   }

   /*
   show all login sessions
   optional parameter <start>  = Unix timestamp in seconds
   optional parameter <end>  = Unix timestamp in seconds
   NOTE: defaults to the past 7*24 hours
   returns an array of login session objects   
   */
   public function stat_sessions($start = NULL, $end = NULL) {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $end              = is_null($end) ? time() : $end;
      $start            = is_null($start) ? $end-(7*24*3600) : $start;
      $json             = json_encode(array('type'=> 'all', 'start' => $start, 'end' => $end));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/stat/session","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $session) {
                  $return[]= $session;
               }
            }
         }
      }
      return $return;
   }

   /*
   show all authorizations
   optional parameter <start> = Unix timestamp in seconds
   optional parameter <end> = Unix timestamp in seconds
   NOTE: defaults to the past 7*24 hours
   returns an array of authorization objects
   */
   public function stat_auths($start = NULL, $end = NULL) {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $end              = is_null($end) ? time() : $end;
      $start            = is_null($start) ? $end-(7*24*3600) : $start;
      $json             = json_encode(array('start' => $start, 'end' => $end));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/stat/authorization","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $auth) {
                  $return[]= $auth;
               }
            }
         }
      }
      return $return;
   }

   /*
   get details of all clients ever connected to the site
   optional parameter <historyhours> = hours to go back (default is 8760 hours or 1 year)
   returns an array of client objects
   NOTES:
   - <historyhours> is only used to select clients that were online within that period
   - the returned stats per client are all-time totals, irrespective of the "within" value
   */
   public function stat_allusers($historyhours = 8760) {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $json             = json_encode(array('type' => 'all', 'conn' => 'all', 'within' => $historyhours));
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/stat/alluser','json='.$json));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $stats) {
                  $return[]= $stats;
               }
            }
         }
      }
      return $return;
   }

   /*
   list guests
   returns an array of guest objects with valid access
   required parameter <within> = time frame in hours to go back to list guests with valid access (default = 24*365 hours)
   */
   public function list_guests_within($within) {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $json             = json_encode(array('within' => $within));
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/stat/guest','json='.$json));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $guest) {
                  $return[]= $guest;
               }
            }
         }
      }
      return $return;
   }

   /*
   list clients
   returns an array of client objects
   */
   public function list_guests() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $json             = json_encode(array());
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/stat/guest","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $guest) {
                  $return[]= $guest;
               }
            }
         }
      }
      return $return;
   }

   /*
   list clients
   returns a array of client objects
   */
   public function list_clients() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $json             = json_encode(array());
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/stat/sta","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $client) {
                  $return[]= $client;
               }
            }
         }
      }
      return $return;
   }

   /*
   gets data for a single client
   required parameter <client_mac>
   returns an object with the client information
   */
   public function stat_client($client_mac) {
      if (!$this->is_loggedin) return false;
      $return           = false;
	    $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/stat/user/'.$client_mac));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $client) {
                  $return[]= $client;
               }
            }
         }
      }
      return $return;
   }

   /*
   list user groups
   returns an array of user group objects
   */
   public function list_usergroups() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/list/usergroup'));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $usergroup) {
                  $return[]= $usergroup;
               }
            }
         }
      }
      return $return;
   }
   
   /*
   assign user to another group
   required parameter <user_id> = id of the user to be modified
   required parameter <group_id> = id of the user group to assign user to
   return true on success
   */
   public function set_usergroup($user_id, $group_id) {
      if (!$this->is_loggedin) return false;
      $return           = false;
      $json             = json_encode(array('usergroup_id' => $group_id, "noted" => false));
	    $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/upd/user/'.$user_id,'json='.$json));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            $return = true;
         }
      }
      return $return;
   }   

   /*
   list health metrics
   returns a array of health metric objects
   */
   public function list_health() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $json             = json_encode(array());
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/stat/health","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $health) {
                  $return[]= $health;
               }
            }
         }
      }
      return $return;
   }

   /*
   list dashboard metrics
   returns an array of dashboard metric objects (available since controller version 4.9.1.alpha)
   */
   public function list_dashboard() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/stat/dashboard'));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $dashboard) {
                  $return[]= $dashboard;
               }
            }
         }
      }
      return $return;
   }

   /*
   list users
   returns a array of known user objects
   */
   public function list_users() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $json             = json_encode(array());
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/list/user","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $user) {
                  $return[]= $user;
               }
            }
         }
      }
      return $return;
   }

   /*
   list access points and other devices under management of the controller (USW and/or USG devices)
   returns an array of known device objects (or a single device when using the <device_mac> parameter)
   optional parameter <device_mac> = the MAC address of a single device for which the call must be made
   */
   public function list_aps($device_mac = NULL) {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/stat/device/'.$device_mac));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $ap) {
                  $return[]= $ap;
               }
            }
         }
      }
      return $return;
   }

   /*
   list rogue access points
   optional parameter <within> = hours to go back to list discovered "rogue" access points (default = 24 hours)
   returns an array of known rogue access point objects
   */
   public function list_rogueaps($within = '24') {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $json             = json_encode(array('within' => $within));
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/stat/rogueap','json='.$json));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $rogue) {
                  $return[]= $rogue;
               }
            }
         }
      }
      return $return;
   }

   /*
   list sites
   returns a list sites hosted on this controller with some details
   */
   public function list_sites() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content          = $this->exec_curl($this->baseurl."/api/self/sites");
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $site) {
                  $return[]= $site;
               }
            }
         }
      }
      return $return;
   }

   /*
   add a site
   returns an array containing a single object with attributes of the new site ("_id", "desc", "name") on success
   required parameter <description> = the long name for the new site
   NOTE: immediately after being added, the new site will be included in the output of the "list_sites" function
   */
   public function add_site($description) {
      if (!$this->is_loggedin) return false;
      $return           = false;
      $json             = json_encode(array('desc' => $description, 'cmd' => 'add-site'));
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/cmd/sitemgr','json='.$json));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $site) {
                  $return[]= $site;
               }
            }
         }
      }
      return $return;
   }

   /*
   list wlan_groups
   returns a array of known wlan_groups
   */
   public function list_wlan_groups() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/list/wlangroup");
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $wlan_group) {
                  $return[]= $wlan_group;
               }
            }
         }
      }
      return $return;
   }
   
   /*
   stat sysinfo
   returns a array of known sysinfo data
   */
   public function stat_sysinfo() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/stat/sysinfo");
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $sysinfo) {
                  $return[]= $sysinfo;
               }
            }
         }
      }
      return $return;
   }

   /*
   list self
   returns an array of information about the logged in user
   */
   public function list_self() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/self'));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $selfinfo) {
                  $return[]= $selfinfo;
               }
            }
         }
      }
      return $return;
   }

   /*
   list networkconf
   returns an array of network configuration data
   */
   public function list_networkconf() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/list/networkconf'));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $networkconf) {
                  $return[]= $networkconf;
               }
            }
         }
      }
      return $return;
   }

   /*
   stat vouchers
   optional parameter <create_time> = Unix timestamp in seconds
   returns an array of hotspot voucher objects
   */
   public function stat_voucher($create_time = NULL) {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $json             = json_encode(array());
      if (trim($create_time) != NULL) {
        $json=json_encode(array('create_time' => $create_time));
      }
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/stat/voucher','json='.$json));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $voucher) {
                  $return[]= $voucher;
               }
            }
         }
      }
      return $return;
   }

   /*
   stat payment
   returns an array of hotspot payments
   */
   public function stat_payment() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/stat/payment'));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $payment) {
                  $return[]= $payment;
               }
            }
         }
      }
      return $return;
   }

   /*
   list hotspot operators
   returns an array of hotspot operators
   */
   public function list_hotspotop() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/list/hotspotop'));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $hotspotop) {
                  $return[]= $hotspotop;
               }
            }
         }
      }
      return $return;
   }

   /*
   create voucher(s)
   required parameter <minutes> = minutes the voucher is valid after activation
   required parameter <number_of_vouchers_to_create>
   optional parameter <note> = note text to add to voucher when printing
   optional parameter <up> = upload speed limit in kbps
   optional parameter <down> = download speed limit in kbps
   optional parameter <MBytes> = data transfer limit in MB
   returns an array of vouchers codes (NOTE: without the "-" in the middle)
   */
   public function create_voucher($minutes, $number_of_vouchers_to_create = 1, $note = NULL, $up = NULL, $down = NULL, $MBytes = NULL) {
      if (!$this->is_loggedin) return false;
      $return   = array();
      $json     = array('cmd' => 'create-voucher', 'expire' => $minutes, 'n' => $number_of_vouchers_to_create);

      /*
      if we have received values for note/up/down/MBytes we append them to the payload array to be submitted
      */
      if (isset($note))   $json += array('note' => trim($note));
      if (isset($up))     $json += array('up' => $up);
      if (isset($down))   $json += array('down' => $down);
      if (isset($MBytes)) $json += array('bytes' => $MBytes);

      $json             = json_encode($json);
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/cmd/hotspot','json='.$json));
      if ($content_decoded->meta->rc == 'ok') {
         if (is_array($content_decoded->data)) {
            $obj = $content_decoded->data[0];
            foreach ($this->get_vouchers($obj->create_time) as $voucher)  {
               $return[]= $voucher->code;
            }
         }
      }
      return $return;
   }

   /*
   list port forwarding stats
   returns an array of port forwarding stats
   */
   public function list_portforward_stats() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content_decoded  = json_decode($this->exec_curl($this->baseurl.'/api/s/'.$this->site.'/stat/portforward'));
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == 'ok') {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $portforward) {
                  $return[]= $portforward;
               }
            }
         }
      }
      return $return;
   }

   /*
   list port forwarding settings
   returns a array of the site port forwarding settings
   */
   public function list_portforwarding() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/list/portforward");
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $portforward) {
                  $return[]= $portforward;
               }
            }
         }
      }
      return $return;
   }
   
   /*
   list dynamic dns settings
   returns a array of the site port dynamic dns settings
   */
   public function list_dynamicdns() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/list/dynamicdns");
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $dynamicdns) {
                  $return[]= $dynamicdns;
               }
            }
         }
      }
      return $return;
   }
   
   /*
   list port configuration
   returns a array of the site port configuration
   */
   public function list_portconf() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/list/portconf");
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $portconf) {
                  $return[]= $portconf;
               }
            }
         }
      }
      return $return;
   }
   
   /*
   list VoIP extensions
   returns a array of the site VoIP extensions
   */
   public function list_extension() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/list/extension");
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $extension) {
                  $return[]= $extension;
               }
            }
         }
      }
      return $return;
   }
      
   /*
   list site settings
   returns a array of the site configuration settings
   */
   public function list_settings() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/get/setting");
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $setting) {
                  $return[]= $setting;
               }
            }
         }
      }
      return $return;
   }

   /*
   reboot an access point
   parameter <MAC address>
   return true on success
   */
   public function restart_ap($mac) {
      if (!$this->is_loggedin) return false;
      $mac              = strtolower($mac);
      $return           = false;
      $json             = json_encode(array('cmd' => 'restart', 'mac' => $mac));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/cmd/devmgr","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            $return = true;
         }
      }
      return $return;
   }

   /*
   start flashing LED of an access point for locating purposes
   parameter <MAC address>
   return true on success
   */
   public function set_locate_ap($mac) {
      if (!$this->is_loggedin) return false;
      $mac              = strtolower($mac);
      $return           = false;
      $json             = json_encode(array('cmd' => 'set-locate', 'mac' => $mac));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/cmd/devmgr","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            $return = true;
         }
      }
      return $return;
   }

   /*
   start flashing LED of an access point for locating purposes
   parameter <MAC address>
   return true on success
   */
   public function unset_locate_ap($mac) {
      if (!$this->is_loggedin) return false;
      $mac              = strtolower($mac);
      $return           = false;
      $json             = json_encode(array('cmd' => 'unset-locate', 'mac' => $mac));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/cmd/devmgr","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            $return = true;
         }
      }
      return $return;
   }

   /*
   switch LEDs of all the access points ON
   return true on success
   */
   public function site_ledson() {
      if (!$this->is_loggedin) return false;
      $return           = false;
      $json             = json_encode(array('led_enabled' => true));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/set/setting/mgmt","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            $return = true;
         }
      }
      return $return;
   }

   /*
   switch LEDs of all the access points OFF
   return true on success
   */
   public function site_ledsoff() {
      if (!$this->is_loggedin) return false;
      $return           = false;
      $json             = json_encode(array('led_enabled' => false));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/set/setting/mgmt","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            $return = true;
         }
      }
      return $return;
   }

   /*
   set access point radio settings
   required parameter <ap_id>
   required parameter <radio>(default=ng)
   required parameter <channel>
   required parameter <ht>(default=20)
   required parameter <tx_power_mode>
   required parameter <tx_power>(default=0)
   return true on success
   */
   public function set_ap_radiosettings($ap_id, $radio, $channel, $ht, $tx_power_mode, $tx_power) {
      if (!$this->is_loggedin) return false;
      $return           = false;
      $jsonsettings     = json_encode(array('radio' => $radio, 'channel' => $channel, 'ht' => $ht, 'tx_power_mode' => $tx_power_mode, 'tx_power' =>$tx_power));
      $json             = '{"radio_table": ['.$jsonsettings.']}';
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/upd/device/".$ap_id,"json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            $return = true;
         }
      }
      return $return;
   }

   /*
   set guest login settings
   required parameter <portal_enabled>
   required parameter <portal_customized>
   required parameter <redirect_enabled>
   required parameter <redirect_url>
   required parameter <x_password>
   required parameter <expire_number>
   required parameter <expire_unit>
   required parameter <site_id>
   return true on success
   NOTE: both portal parameters are set to the same value!
   */
   public function set_guestlogin_settings($portal_enabled, $portal_customized, $redirect_enabled, $redirect_url, $x_password, $expire_number, $expire_unit, $site_id) {
      if (!$this->is_loggedin) return false;
      $return           =false;
      $json = json_encode(array('portal_enabled' => $portal_enabled, 'portal_customized' => $portal_customized,
                                'redirect_enabled' => $redirect_enabled, 'redirect_url' => $redirect_url,
                                'x_password' => $x_password, 'expire_number' => $expire_number,
                                'expire_unit' => $expire_unit, 'site_id' => $site_id), JSON_UNESCAPED_SLASHES);
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/set/setting/guest_access","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            $return = true;
         }
      }
      return $return;
   }

   /*
   rename access point
   required parameter <ap_id>
   required parameter <apname>
   return true on success
   */
   public function rename_ap($ap_id, $apname) {
      if (!$this->is_loggedin) return false;
      $return           = false;
      $json             = json_encode(array('name' => $apname));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/upd/device/".$ap_id,"json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            $return = true;
         }
      }
      return $return;
   }

   /*
   set wlan settings
   required parameter <wlan_id>
   required parameter <name>
   required parameter <x_passphrase>
   return true on success
   */
   public function set_wlansettings($wlan_id, $name, $x_passphrase) {
      if (!$this->is_loggedin) return false;
      $return           = false;
      $json             = json_encode(array('name' => $name, 'x_passphrase' => $x_passphrase));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/upd/wlanconf/".$wlan_id,"json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            $return = true;
         }
      }
      return $return;
   }
    
   /*
   list events
   returns a array of known events
   */
   public function list_events() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $json             = json_encode(array());
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/stat/event","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $event) {
                  $return[]= $event;
               }
            }
         }
      }
      return $return;
   }

   /*
   list wireless settings
   returns a array of wireless networks and settings
   */
   public function list_wlanconf() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $json             = json_encode(array());
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/list/wlanconf","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $wlan) {
                  $return[]= $wlan;
               }
            }
         }
      }
      return $return;
   }

   /*
   list alarms
   returns a array of known alarms
   */
   public function list_alarms() {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $json             = json_encode(array());
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/list/alarm","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $alarm) {
                  $return[]= $alarm;
               }
            }
         }
      }
      return $return;
   }

   /*
   list vouchers
   returns a array of voucher objects
   */
   public function get_vouchers($create_time="") {
      if (!$this->is_loggedin) return false;
      $return           = array();
      $json             = json_encode(array());
      if (trim($create_time) != "") {
        $json=json_encode(array('create_time' => $create_time));
      }
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/stat/voucher","json=".$json);
      $content_decoded  = json_decode($content);
      if (isset($content_decoded->meta->rc)) {
         if ($content_decoded->meta->rc == "ok") {
            if (is_array($content_decoded->data)) {
               foreach ($content_decoded->data as $voucher) {
                  $return[]= $voucher;
               }
            }
         }
      }
      return $return;
   }

   /*
   format data, input bytes it spits out its conversion to MB, GB, KB etc...
   */   
   public function formatBytes($bytes, $precision = 2) { 
      $units = array('B', 'KB', 'MB', 'GB', 'TB'); 

      $bytes = max($bytes, 0); 
      $pow = floor(($bytes ? log($bytes) : 0) / log(1024)); 
      $pow = min($pow, count($units) - 1); 

      // Uncomment one of the following alternatives
      // $bytes /= pow(1024, $pow);
      $bytes /= (1 << (10 * $pow)); 

      return round($bytes, $precision) . ' ' . $units[$pow]; 
   }
   
   /*
   delete voucher
   returns false on error array of data returned by unifi controller
   */
   public function delete_voucher($id) {
      if (!$this->is_loggedin || $id == NULL || $id == '') return false;
      $json             = json_encode(array('cmd' => 'delete-voucher', '_id' => $id));
      $content          = $this->exec_curl($this->baseurl."/api/s/".$this->site."/cmd/hotspot","json=".$json);
      // TODO: use true or false on return, see authorize_guest return
      return json_decode($content);
   }

   private function exec_curl($url, $data = "") {
      $ch=$this->get_curl_obj();
      curl_setopt($ch, CURLOPT_URL, $url);
      if (trim($data) != "") {
         curl_setopt($ch, CURLOPT_POSTFIELDS,$data);
      } else {
         curl_setopt($ch, CURLOPT_POST, FALSE);
      }
      $content = curl_exec($ch);
      if ($this->debug === true) {
         print "<pre>";
         print "\n\n-----cURL INFO---------------\n\n";
         print_r (curl_getinfo($ch));
         print "\n\n-----URL & PAYLOAD-----------\n\n";
         print $url."\n";
         print $data;
         print "\n\n-----RESPONSE----------------\n\n";
         print $content;
         print "\n\n-----------------------------\n\n";
         print "</pre>";
      }
      //if (curl_exec($ch) === false) {
      //   error_log('curl error: ' . curl_error($ch));
      //}   
      curl_close ($ch);
      return $content;
   }

   private function get_curl_obj() {
      $ch = curl_init();
      curl_setopt($ch, CURLOPT_POST, TRUE);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
      curl_setopt($ch , CURLOPT_RETURNTRANSFER, TRUE);
      if ($this->debug === true) {
         curl_setopt($ch, CURLOPT_VERBOSE, TRUE);
      }
      if ($this->cookies != "") {
         curl_setopt($ch, CURLOPT_COOKIE,  $this->cookies);
      }
      return $ch;
   }
   

}
?>
