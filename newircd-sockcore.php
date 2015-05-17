<?php
function __autoload($c) {
	$c = strtr($c,"_","/");
	require_once("./modules/".$c.".php");
}

//error_reporting(0);
global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;

function parseConf($linename,$rehash) {
global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
	// Returns an array containing at the first dimension
	// all lines with the $linename in the config
	// and at the second dimension the items on that line.
	// For .rehash requires to be done for every module
	if ($linename == "") return false;
	if (strcasecmp($rehash,"yes"))
		$file = file_get_contents("./".$mods["%cfgfile%"]);
	$filelines = explode("\n",$file);
	$lines = array();
	foreach ($filelines as $line) {
		$linearr = explode("%",$line);
		if ($linearr[0] == $linename)
			$lines[] = $linearr;
	}
	return $lines;
}

function regCallback($object, $func, $protocolWord){
global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
	$callbacks[$protocolWord][] = array($object, $func);
}

function regEvent($object, $func, $protocolWord){
global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
	$mods["%event%"][$protocolWord][] = array($object, $func);
}

function unregCallback($object, $func, $protocolWord){
global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
	$cb = array_search(array($object,$func),$callbacks[$protocolWord],TRUE);
	unset($callbacks[$protocolWord][$cb]);
}

function unregEvent($object, $func, $protocolWord){
global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
	$mods["%event%"][$protocolWord][] = array($object, $func);
}

function regLEvent($func, $protocolWord){
global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
	$mods["%event%"][$protocolWord][] = $func;
}

function callCallbacks($get){
global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
	// Format for a parsed line is:
	/*
	 * $get[0] = Command (or any chosen special word, just has to be standard :P)
	 * $get[1] = Source (or local server if no source)
	 * $get[2] and so on = Rest of arguments
	 */
	if ($callbacks[$get["cmd"]])
		foreach ($callbacks[$get["cmd"]] as $callback) call_user_func($callback,array_slice($get,1));
	if ($callbacks[$get["cmd"]]) return;
	if ($callbacks[$get[0]])
		foreach ($callbacks[$get[0]] as $callback) call_user_func($callback,array_slice($get,1));
}

function callEvents($get){
global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
	// Format for a parsed line is:
	/*
	 * $get[0] = Command (or any chosen special word, just has to be standard :P)
	 * $get[1] = Source (or local server if no source)
	 * $get[2] and so on = Rest of arguments
	 */
	if ($mods["%event%"][$get["cmd"]])
		foreach ($mods["%event%"][$get["cmd"]] as $callback) call_user_func($callback,$get);
}

define("DNSBL",0x1);
define("NORMLOOKUP",0x2);
define("V6LOOKUP",0x4);
define("REVLOOKUP",0x8);

class SockSelect {

	function dig($name, $qtype, $dnsbl = ".", $isdnsbl = false) {
		$type = 0;
		if ($isdnsbl >= 1) {
			$isipv6 = (strpos($name, ":") !== FALSE);
			if ($dnsbl == ".") return false;
			if ($isipv6) {
				$type = $type | V6LOOKUP;
			}
			$type = $type | DNSBL;
			$type = $type | REVLOOKUP;
		}
		if (!$isdnsbl) $type = NORMLOOKUP;
		if ($qtype == "PTR") {
			$isipv6 = (strpos($name, ":") !== FALSE);
			if ($isipv6) {
				$type = $type | REVLOOKUP;
			}
			$type = $type | REVLOOKUP;
		}
		if ($type & 0x8) {
			if ($type & V6LOOKUP) $rdns = implode(".",str_split(strrev(implode("",explode(":",$name)))));
			else $rdns = implode(".",array_reverse(explode(".",$name)));
			$dname = $rdns;
			if (($type & 0x4) and ($type & 0x1)) $dname .= ".ip6.arpa";
			else if ($type & 0x2) $dname .= ".in-addr.arpa";
			else {
				$dname .= ".".$dnsbl;
			}
		} else $dname = $name;
		$dnsname = "timeout 0.1s host ".escapeshellarg($dname)." -t ".escapeshellarg(strtoupper($qtype))." | head -n 1";
		echo $dnsname.PHP_EOL;
		$out = shell_exec($dnsname);
		$o = explode($out, " ");
		$out = array_reverse($o)[0];
		echo $out.PHP_EOL;
		if ($type & 0x1) {
			$num = explode(".",$out);
			$numreply = 0;
			$numreply = $numreply + $num[3];
			$numreply = $numreply + ($num[2] << 8);
			$numreply = $numreply + ($num[1] << 16);
			// We'll return the pton result :P
			return $numreply;
		}
		return $out;
	}
	function __construct($initlisteners) {
		/*
		switch (TRUE) {
			case ($bck & Ev::BACKEND_KQUEUE):
				$backend = Ev::BACKEND_KQUEUE;
			break;
			case ($bck & Ev::BACKEND_EPOLL):
				$backend = Ev::BACKEND_EPOLL;
			break;
			default: die("Could not find suitable I/O backend");
			break;
		}
		$this->bck = $backend;
		$this->r = Ev::READ;
		$this->w = Ev::WRITE;
		$this->ev = new EvLoop($backend); 
		* No more do we use Ev. Back to plain simple Select looping. :)
		*/
		$GLOBALS["mods"]["%socket%"] = array();
		$GLOBALS["callbacks"]["%input%"] = array();
		if (!$initlisteners) return;
		foreach (parseConf("Pssl",false) as $s) $this->listen_ssl($s[1],$s[2]);
		foreach (parseConf("P",false) as $s) $this->listen($s[1]);
		return;
	}
	
	function loop(){
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		$lis = $this->listeners;
		@stream_select($lis, $r = NULL, $e = NULL, 0, 10000);
		if (isset($lis)) foreach ($lis as $soc) $this->accept($soc);
		$r = $w = $e = $GLOBALS["mods"]["%socket%"];
		@stream_select($r, $w, $e, 0, 20000);
		foreach ($r as $fi) call_user_func(array($this,"do_read"),$fi);
		foreach ($r as $fi) call_user_func(array($this,"do_write"),$fi);
		foreach ($w as $fi) call_user_func(array($this,"do_write"),$fi);
		foreach ($e as $fi) {
			unset($GLOBALS["mods"]["%socket%"][(int)$fi],$callbacks["%readable%"][(int)$fi],$callbacks["%writable%"][(int)$fi]);
			foreach ($callbacks["%exit%"] as $cb) call_user_func($cb,$fi);
		}
		foreach ($r as $fi) if (feof($fi)) unset($GLOBALS["mods"]["%client%"][(int)$fi]);
		//echo $this->ev->run(); //Not going to use our ev system.
	}

	function connect($url,$opt,$callback) {
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		$opts = stream_context_create($opt);
		$fd = stream_socket_client($url,$err,$errs,2,STREAM_CLIENT_CONNECT,$opts);
		stream_set_read_buffer($fd,0);
		stream_set_write_buffer($fd,0);
		$mods["%socket%"][] = $fd;
		$callbacks["%input%"][(int)$fd][] = $callback;
		return $fd;
	}
	
	function accept($fd) {
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		$fi = stream_socket_accept($fd);
		$GLOBALS["mods"]["%writebuf%"][(int)$fi] = "";
		foreach ($callbacks["%new%"] as $cb) call_user_func($cb,$fi);
		foreach ($callbacks["%socknew%"][(int)$fd] as $cb) call_user_func($cb,$fi);
		$GLOBALS["mods"]["%socket%"][] = $fi;
		$callbacks["%readable%"][(int)$fi] = array($this,"do_read");
		$callbacks["%writable%"][(int)$fi] = array($this,"do_write");
		$this->do_write($fi);
		$sockname = stream_socket_get_name($fi, TRUE);
		$sockname = implode(":",explode(":",$sockname,-1));
		$sockdns = trim($this->dig($sockname,"PTR"));
		$GLOBALS["mods"]["%sockip%"][(int)$fi] = $sockname;
		if ($sockdns == "") {
			$GLOBALS["mods"]["%sockname%"][(int)$fi] = $sockname;
			return;
		}
		if ($sockname == $this->dig($sockdns,"A")) {
			$sockname = $this->dig($sockdns,"A");
		} else if ($sockname == $this->dig($sockdns,"AAAA")) {
			$sockname = $this->dig($sockdns,"AAAA");
		}
		$GLOBALS["mods"]["%sockname%"][(int)$fi] = $sockname;
	}
	
	function do_read($fd) {
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		$data = trim(fgets($fd),"\r\n");
		if (feof($fd)) {	foreach ($callbacks["%exit%"] as $cb) call_user_func($cb,$fd);
			unset($GLOBALS["mods"]["%socket%"][array_search($fd,$GLOBALS["mods"]["%socket%"])],$callbacks["%readable%"][(int)$fd],$callbacks["%writable%"][(int)$fd]);
			return;
		}
		foreach ($callbacks["%input%"][(int)$fd] as $cb) {
			call_user_func($cb,$fd,$data); // Call the callback with the data we received.
		}
	}
	
	function do_write($fd) {
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		if ($GLOBALS["mods"]["%writebuf%"][(int)$fd] == "") return;
		fwrite($fd,$GLOBALS["mods"]["%writebuf%"][(int)$fd]);
		$GLOBALS["mods"]["%writebuf%"][(int)$fd] = "";
	}
	
	function write($fd,$data) {
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		$GLOBALS["mods"]["%writebuf%"][(int)$fd] .= $data;
	}
	
	function listen_ssl ($listen, $pem, $cb = NULL) {
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		$opt = array("ssl" => array("local_cert" => $pem, "capture_peer_cert" => TRUE));
		$opts = stream_context_create($opt);
		$fd = stream_socket_server("ssl://".$listen,$err,$errs,STREAM_SERVER_BIND|STREAM_SERVER_LISTEN,$opts);
		$this->listeners[]=$fd;
		if ($cb) $callbacks["%socknew%"][(int)$fd]=$cb;
		return $fd;
	}
	
	function listen ($listen, $cb = NULL) {
		global $confItems, $file, $opMode, $Mline, $protofunc, $mods, $callbacks, $socket;
		$fd = stream_socket_server("tcp://".$listen);
		$this->listeners[]=$fd;
		if ($cb) $callbacks["%socknew%"][(int)$fd]=$cb;
		return $fd;
	}
}
