#!/usr/bin/php
<?php
$ini = parse_ini_file('ircd.conf',true);
$inimain = $ini['main'];
print_r($ini);
$CONST_MAX_USERS = 1024;
$CONST_VERSION = "1-beta1";
$CONST_ISUPPORT = "ircd-ronsor $CONST_VERSION NICKLEN=12 CHANTYPES=#&!+ NICKALLOW=AZ,az,09,-_[] PREFIX=(ov)@+ NETWORK=IRC";
//<?php
//error_reporting(0);
$clients = array();
global $clients;
global $inimain;
global $ini;
$socket = socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
if(!socket_bind($socket,'0.0.0.0',$ini['main']['port'])){
	if(!socket_bind($socket,'0.0.0.0',$ini['main']['altport'])){
			die("Cannot bind to port");
	}
}
socket_listen($socket);
socket_set_nonblock($socket);
$clients = Array();
while(true)
{
    if(($newc = socket_accept($socket)) !== false)
    {
	
        echo "Client $newc has connected\n";
        
	$curclient = Array();
	$curclient['sock'] = $newc;
	socket_getpeername($newc,$sckhost);
	$curclient['host'] = $sckhost;
        $curclient['cloak'] = hash('crc32',$sckhost).".hidden";

	$clients[] = $curclient;
	sockput($curclient,":".$inimain['name']." NOTICE * :I am resolving your hostname...");
	sockput($curclient,":".$inimain['name']." 005 * ".$CONST_ISUPPORT." :are my settings specified in ircd.conf");
	if(isset($ini['ban']['ip'][$sckhost])){
	sockput($curclient,":".$inimain['name']." NOTICE * :I don't like you.");
	sockput($curclient,"ERROR :You're banned $sckhost ".$ini['ban']['ip'][$sckhost]);
	socket_close($newc);
	}
    } else {
	//print_r($clients);
    foreach($clients as $clientn => $clientid){
	$csock = $clientid;
	//echo $clientn."\n";
	$sctgotn = socket_recv($csock['sock'], $sctgotx, 4096, 0x40);
       $sctgotx = str_replace("\r","",$sctgotx);
	foreach(explode("\n",$sctgotx) as $sctgot){
	//$sckreadn = socket_read($csock, 1);
	if(!$sctgot == false){
//	echo $sctgot."\n";
	}
	if(socket_last_error() != 0 && socket_last_error() != 11){
                //kill_user($clients,$clients[$clientn]['nick'],socket_strerror(socket_last_error()));
		//unset($clients[$clientn]);
		echo socket_last_error()." - ";
		echo socket_strerror(socket_last_error())."\n";
		socket_clear_error();
	}
	if(!empty($sctgot)){
	$nparv = explode(' ',$sctgot);
	$parv = explode(' ',str_replace(":","",strtolower($sctgot)));
	//print_r($parv);
	suserput(Array( 'nick' => nuh($csock)),$sctgot);
	switch(strtolower($parv[0])){
		case 'squit':
                case 'kill':
                $killreason = explode(':',$sctgot)[1];
                if(!empty($clientid['priv'])){
                kill_user($clients,$parv[1],"You've been killed @TARGET $killreason");
                }
       		break;
		case 'slink':
		case 'sconnect':
		case 'connect':
		$clientx = Array( 'sock' => socket_create(AF_INET,SOCK_STREAM,SOL_TCP), 'host' => '255.255.255.255' );
		socket_connect($clientx['sock'],$parv[1],$parv[2]);
		sockput($clientx,"SERVER ".$inimain['name']." ".$parv[3]);
		sockput($clientx,"005 ".$CONST_ISUPPORT);
		sockput($clientx,"001 :Linking complete");
		$clients[] = $clientx;
		break;
                case 'whois':
                foreach($clients as $ct){
                if ($ct['nick'] == $parv[1]){
                        sockput($csock,":".$inimain['name']." 311 ".$csock['nick']." ".$ct['nick']." ".$ct['nick']." ".$ct['host']." * :".$ct['nick']);
                        sockput($csock,":".$inimain['name']." 318 ".$csock['nick']." ".$ct['nick']." :End of 311 RPL_WHOIS");
                }
                }
                break;
                case 'names':
                sockput($csock,names($csock,$parv[1]));
		
          	suserput($csock,"NAMES ".$parv[1]);
	        break;

                case 'quit':
                kill_user($clients,$csock['nick'],"Lost route to host");
                break;
		case 'server':
		$clients[$clientn]['server'] = 1;
		opersend(":".$parv[1]." NOTICE OPERS :*** Connecting server (USE /SQUIT SERVER to stop): ".$parv[1]);
                sockput($csock,"SERVER ".$inimain['name']." ".$ini['main']['opers'][$csock['nick']]);
		case 'oper':
                if(strtolower($inimain['opers'][$parv[1]]) == $parv[2]){
                 $clients[$clientn]['priv'] = "o";
                } else {
		sockput($csock,":".$inimain['name']." NOTICE * :Wrong information");
		kill_user($clients,$parv[1],"Wrong Oper Credentials");
		}
		case 'nick':
                if(findnick($parv[1]) == true){
			sockput($csock,"NOTICE * :Nickname taken. Auto-generating nickname");
 			$parv[1] = $parv[1].rand(100,999);
		}
                if(empty($clientid['nick'])){
		sockput($csock,":".$inimain['name']." 001 ".$parv[1]." :[001] Welcome to IRC!");
		sockput($csock,":".$inimain['name']." 372 ".$parv[1]." :*** ".$inimain['motd']);
		serverput($clients,":".$inimain['name']." SUSER ".$parv[1]." ".$clientid['host']);
		$clients[$clientn]['nick'] = $parv[1];
		$clients[$clientn]['ident'] = $parv[1];
                 } else {
                $clients[$clientn]['nick'] = $parv[1];
                sockput($csock,":".nuh($csock)." NICK ".$parv[1]);
                }
                
		break;
		case 'suser':
		$clients[] = Array('nick' => $parv[1], 'ident' => $parv[1], 'host' => $host, 'remote' => 1,$sock = $csock['sock']);
		break;
		case 'ping':
		sockput($csock,"PONG ".$parv[1]);
		break;
		case 'join':
		foreach(explode(",",$parv[1]) as $chanx){
		sockput($csock,":".nuh($clientid)." JOIN ".$chanx);
		if(!isset($channels[$chanx])){
			$channels[$chanx][] = $clientn;
			$chanops[$chanx][] = $clientn;
			sockput($csock,":".$inimain['name']." MODE ".$chanx." +ov ".$csock['nick']." ".$csock['nick']);
		} else {
			foreach($channels[$parv[1]] as $n => $f){
				sockput($clients[$f],":".nuh($csock)." JOIN ".$chanx);
			}
			sockput($csock,":".$inimain['name']." 332 ".$csock['nick']." ".$parv[1]." :".$chantopics[$parv[1]]);
                        $channels[$parv[1]][] = $clientn;
		}
		sockput($csock,names($csock,$chanx));
		}
		break;
		case 'topic':
		if(!empty($parv[2])){
		if(in_array($clientn,$chanops[$parv[1]],true) || $csock['priv'] = 'o'){
			$tpc = str_replace($nparv[0]." ".$nparv[1]." :","",$sctgot);
			$chantopics[$parv[1]] = $tpc;
			sendtochan($channels[$parv[1]],":".nuh($csock)." TOPIC ".$parv[1]." :".$tpc);
		} else {
			sockput($csock,":".$inimain['name']." TOPIC ".$csock['nick']." ".$parv[2]." :".$chantopics[$parv[1]]);
		}
		}
		break;
		case 'list':
		foreach($channels as $chn => $uns){
			sockput($csock,":".$inimain['name']." 322 ".$csock['nick']." ".$chn." :0 ".$chantopics[$chn]);
		}
		break;
		case 'mode':
		if($parv[1] == $csock['nick']){
		sockput($csock,":".$inimain['name']." 300 * E_NOIMPL :Error setting user modes: Not implemented");
		} else {
		switch($parv[2]){
		case '+o':
		if(in_array($clientn,$chanops[$parv[1]],true) || !empty($csock['priv'])){
			sendtochan($channels[$parv[1]],":".nuh($csock)." MODE ".$parv[1]." +o ".$parv[3]);
			$chanops[$parv[1]][] = chanfindnick($channels[$parv[1]],$parv[3]);
		} else {
			sendtochan($channels[$parv[1]],":".$inimain['main']." 300 ".$parv[1]." E_NOCHOPS :*** Cannot set mode +o without ops ".nuh($csock));
		}
		break;
		case '-o':
		if(in_array($clientn,$chanops[$parv[1]])){
			sendtochan($channels[$parv[1]],":".nuh($csock)." MODE ".$parv[1]." -o ".$parv[3]);
			$chanops[$parv[1]][chanfindnick($chanops[$parv[1]],$parv[3])] = 0;
		}
		break;
		default:
			sockput($csock,":".$inimain['main']." 300 ".$csock['nick']." E_INVALIDCHMODE :Invalid channel mode");
		}
		}
		break;
		case 'kick':
			$message = explode(":",$sctgot)[1];
			$target = $parv[2];
			$chan = $parv[1];
			if(in_array($clientn,$chanops[$parv[1]],true) || $csock['priv'] = 'o'){
				foreach($channels[$parv[1]] as $nodx => $nid){
					if($clients[$nid]['nick'] == $target){
						sendtochan($channels[$parv[1]],":".nuh($clients[$nid])." PART ".$parv[1]." :KICKED BY ".nuh($csock)." (".$message.")");
						unset($channels[$chan][$nodx]);
					}
				}
			} else {
						sendtochan($channels[$chan],":".nuh($csock)." NOTICE ".$chan." :Attempted to kick user ".$target." but lacked +o OP");
			}
		break;
		case 'part':
			$target = $csock['nick'];
		foreach($channels[$parv[1]] as $nodx => $nid){
                      if($clients[$nid]['nick'] == $target){
                                 sendtochan($channels[$parv[1]],":".nuh($clients[$nid])." PART ".$parv[1]." :Left");
                                                unset($channels[$parv[1]][$nodx]);
                                        }
                                }
		break;
		case 'notice':
		case 'privmsg':
		$sndmsg = str_replace($nparv[0]." ".$nparv[1]." :","",$sctgot);
		foreach($clients as $cnt){
			if(fnmatch($cnt['nick'],$parv[1]) || fnmatch($cnt['host'],$parv[1]) || fnmatch(nuh($cnt),$parv[1])){
				sockput($cnt,":".nuh($clientid)." ".$nparv[0]." ".$cnt['nick']." :".$sndmsg);
			}
		}
		print_r($channels[$parv[1]]);
		foreach($channels[$parv[1]] as $xp){
			$n = $clients[$xp];
			print_r($n);
                     	//if(){
			echo $xp." SEND ".$clientn."\n";
			if($xp === $clientn){
			echo $xp." NOT(SEND) ".$clientn."\n";
			} else {
			echo $xp." SENT ".$clientn."\n";
			sockput($n,":".nuh($clientid)." ".$nparv[0]." ".$parv[1]." :".$sndmsg);
			}
		}
		
	}
	}
	}
    }
   }
	sleep(1);
}
function sendtochan($chanarr,$mesgstr){
	global $clients;
	foreach($chanarr as $nid => $nod){
		sockput($clients[$nod],$mesgstr);
	}
}
function sockput($sck,$dat){
if(!empty($sck['remote'])){

} else {
socket_write($sck['sock'],$dat."\r\n");
echo $dat."\n";
}
}
function serverput($arr,$dat){
foreach($arr as $clnt){
	if($clnt['server'] == 1){
		sockput($clnt,$dat);
	}
}
}
function chanfindnick($arr,$nick){
	global $clients;
	foreach($arr as $nod => $nid){
		if($clients[$nid]['nick'] == $nick){
			$ret = $nod;
		}
	}
	return $ret;
}
function opersend($msg){
global $clients;
foreach($clients as $cln){
	if($cln['priv'] = "o"){
		sockput($cln,$msg);
	}
}
}
function kill_user(&$cxlients,$target,$reason){
	//print_r($clients);
global $inimain;
global $clients;
foreach($clients as $ncid => $cid){
              
		  if($cid['nick'] == $target){
                sockput($cid,":".$inimain['main']." NOTICE * :*** You are being disconnected.");
                sockput($cid,"ERROR :Force Quit: ".str_replace('@TARGET',$cid['nick']."!@".$cid['host'],$reason));
              foreach($channels as $cna => $chan){
                foreach($chan as $nid => $nus){
                if($nus == $cid){
                foreach($channels[$cna] as $cu){
                sockput($clients[cu],":".nuh($cid)." QUIT :Disconnected");
                }
                $channels[$cname][$nid] = "";
                unset($channels[$cname][$nid]);
                }
                }
                }
		
		sleep(2);
                socket_close($cid['sock']);
                $clients[$ncid] = "";
		unset($clients[$ncid]);
		}
}
}
function findnick($nick){
 global $clients;
	$x = false;
 foreach($clients as $cln){
  if(strtolower($cln['nick']) == strtolower($nick)){
   $x = true;
  }
 }
 return $x;
}
function suserput($uarr,$msg){
global $clients;
global $inimain;
	serverput($clients,"NICK ".$uarr['nick']);
	serverput($clients,$msg);
	serverput($clients,"NICK ".$inimain['name']);
}
function nuh($usr){
if(!$usr['server'] == 1){
$y = $usr['nick']."!".$usr['ident']."@".$usr['host'];
} else {
$y = $usr['nick'];
}
return $y;
}
function names($clxients, $cname){
global $clients;
global $channels;
global $inimain;
$x = ':'.$inimain['name']." 353 ".$clxients['nick']." = ".$cname." :";
foreach($channels[$cname] as $cidfo){
$cinfo = $clients[$cidfo];
$x = $x . $cinfo['nick'] . ' ';
}
return $x;
}
