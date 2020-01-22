package core

import (
	"fmt"
	"strings"
	"testing"
)

func TestAltResolveVariable(t *testing.T) {
	format := `https://brutelogic.com.br/tests/sinks.html?name=[[.custom]]xvlb`
	target := make(map[string]string)
	target["custom"] = "zzz"
	result := AltResolveVariable(format, target)
	fmt.Println(result)
	if result != "2sam1" {
		t.Errorf("Error resolve variable")
	}
}

func TestResolveVariable(t *testing.T) {
	// format := `2{{constructor.constructor('alert(1)')()}}{{.sam}}`
	format := `2 {{constructor('alert(1)')()}} {{.var}}`
	target := make(map[string]string)
	target["var"] = "sam"
	result := ResolveVariable(format, target)
	fmt.Println(result)

	format = `2{{constructor.constructor('alert(1)')()}}{{.sam}}`
	format = `2 {{"{{"}}constructor('alert(1)')()}} {{.var}}`
	result = ResolveVariable(format, target)

	fmt.Println(result)
	if !strings.HasSuffix(result, "sam") {
		t.Errorf("Error resolve variable")
	}
}

func TestParseBurpRequest(t *testing.T) {
	raw := `GET /test HTTP/1.1
Host: cors-test.appspot.com
Connection: close
Accept: */*
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3983.0 Safari/537.36
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Referer: https://a.appspot.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

`

	req := ParseBurpRequest(raw)
	fmt.Println(req.URL)
	fmt.Println(req.Host)
	fmt.Println(req.Path)
	if req.Method == "" {
		t.Errorf("Error parsing Burp")
	}
}

func TestParseBurpResponse(t *testing.T) {
	rawReq := `GET /listproducts.php?cat=1 HTTP/1.1
Host: testphp.vulnweb.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:71.0) Gecko/20100101 Firefox/71.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

`

	rawRes := `HTTP/1.1 200 OK
Server: nginx/1.4.1
Date: Thu, 08 Jan 1970 04:26:25 GMT
Content-Type: text/html
Connection: close
X-Powered-By: PHP/5.3.10-1~lucid+2uwsgi2
Content-Length: 7880

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/main_dynamic_template.dwt.php" codeOutsideHTMLIsLocked="false" -->
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-2">

<!-- InstanceBeginEditable name="document_title_rgn" -->
<title>pictures</title>
<!-- InstanceEndEditable -->
<link rel="stylesheet" href="style.css" type="text/css">
<!-- InstanceBeginEditable name="headers_rgn" -->
<!-- InstanceEndEditable -->
<script language="JavaScript" type="text/JavaScript">
<!--
function MM_reloadPage(init) {  //reloads the window if Nav4 resized
  if (init==true) with (navigator) {if ((appName=="Netscape")&&(parseInt(appVersion)==4)) {
    document.MM_pgW=innerWidth; document.MM_pgH=innerHeight; onresize=MM_reloadPage; }}
  else if (innerWidth!=document.MM_pgW || innerHeight!=document.MM_pgH) location.reload();
}
MM_reloadPage(true);
//-->
</script>

</head>
<body> 
<div id="mainLayer" style="position:absolute; width:700px; z-index:1">
<div id="masthead"> 
  <h1 id="siteName"><a href="https://www.acunetix.com/"><img src="images/logo.gif" width="306" height="38" border="0" alt="Acunetix website security"></a></h1>   
  <h6 id="siteInfo">TEST and Demonstration site for <a href="https://www.acunetix.com/vulnerability-scanner/">Acunetix Web Vulnerability Scanner</a></h6>
  <div id="globalNav"> 
      	<table border="0" cellpadding="0" cellspacing="0" width="100%"><tr>
	<td align="left">
		<a href="index.php">home</a> | <a href="categories.php">categories</a> | <a href="artists.php">artists
		</a> | <a href="disclaimer.php">disclaimer</a> | <a href="cart.php">your cart</a> | 
		<a href="guestbook.php">guestbook</a> | 
		<a href="AJAX/index.php">AJAX Demo</a>
	</td>
	<td align="right">
		</td>
	</tr></table>
  </div> 
</div> 
<!-- end masthead --> 

<!-- begin content -->
<!-- InstanceBeginEditable name="content_rgn" -->
<div id="content">
	<h2 id='pageName'>Posters</h2><div class='story'><a href='product.php?pic=1'><h3>The shore</h3></a><p><a href='showimage.php?file=./pictures/1.jpg' target='_blank'><img style='cursor:pointer' border='0' align='left' src='showimage.php?file=./pictures/1.jpg&size=160' width='160' height='100'></a>Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Donec molestie.
Sed aliquam sem ut arcu.</p><p>painted by: <a href='artists.php?artist=1'>r4w8173</a></p><p><a href='#' onClick="window.open('./comment.php?pid=1','comment','width=500,height=400')">comment on this picture</a></p></div><div class='story'><a href='product.php?pic=2'><h3>Mistery</h3></a><p><a href='showimage.php?file=./pictures/2.jpg' target='_blank'><img style='cursor:pointer' border='0' align='left' src='showimage.php?file=./pictures/2.jpg&size=160' width='160' height='100'></a>Donec molestie.
Sed aliquam sem ut arcu.</p><p>painted by: <a href='artists.php?artist=1'>r4w8173</a></p><p><a href='#' onClick="window.open('./comment.php?pid=2','comment','width=500,height=400')">comment on this picture</a></p></div><div class='story'><a href='product.php?pic=3'><h3>The universe</h3></a><p><a href='showimage.php?file=./pictures/3.jpg' target='_blank'><img style='cursor:pointer' border='0' align='left' src='showimage.php?file=./pictures/3.jpg&size=160' width='160' height='100'></a>Lorem ipsum dolor sit amet. Donec molestie.
Sed aliquam sem ut arcu.</p><p>painted by: <a href='artists.php?artist=1'>r4w8173</a></p><p><a href='#' onClick="window.open('./comment.php?pid=3','comment','width=500,height=400')">comment on this picture</a></p></div><div class='story'><a href='product.php?pic=4'><h3>Walking</h3></a><p><a href='showimage.php?file=./pictures/4.jpg' target='_blank'><img style='cursor:pointer' border='0' align='left' src='showimage.php?file=./pictures/4.jpg&size=160' width='160' height='100'></a>Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Donec molestie.
Sed aliquam sem ut arcu. Phasellus sollicitudin.
</p><p>painted by: <a href='artists.php?artist=1'>r4w8173</a></p><p><a href='#' onClick="window.open('./comment.php?pid=4','comment','width=500,height=400')">comment on this picture</a></p></div><div class='story'><a href='product.php?pic=5'><h3>Mean</h3></a><p><a href='showimage.php?file=./pictures/5.jpg' target='_blank'><img style='cursor:pointer' border='0' align='left' src='showimage.php?file=./pictures/5.jpg&size=160' width='160' height='100'></a>Lorem ipsum dolor sit amet, consectetuer adipiscing elit.</p><p>painted by: <a href='artists.php?artist=1'>r4w8173</a></p><p><a href='#' onClick="window.open('./comment.php?pid=5','comment','width=500,height=400')">comment on this picture</a></p></div><div class='story'><a href='product.php?pic=7'><h3>Trees</h3></a><p><a href='showimage.php?file=./pictures/7.jpg' target='_blank'><img style='cursor:pointer' border='0' align='left' src='showimage.php?file=./pictures/7.jpg&size=160' width='160' height='100'></a>bla bla bla</p><p>painted by: <a href='artists.php?artist=2'>Blad3</a></p><p><a href='#' onClick="window.open('./comment.php?pid=7','comment','width=500,height=400')">comment on this picture</a></p></div></div>
<!-- InstanceEndEditable -->
<!--end content -->

<div id="navBar"> 
  <div id="search"> 
    <form action="search.php?test=query" method="post"> 
      <label>search art</label> 
      <input name="searchFor" type="text" size="10"> 
      <input name="goButton" type="submit" value="go"> 
    </form> 
  </div> 
  <div id="sectionLinks"> 
    <ul> 
      <li><a href="categories.php">Browse categories</a></li> 
      <li><a href="artists.php">Browse artists</a></li> 
      <li><a href="cart.php">Your cart</a></li> 
      <li><a href="login.php">Signup</a></li>
	  <li><a href="userinfo.php">Your profile</a></li>
	  <li><a href="guestbook.php">Our guestbook</a></li>
		<li><a href="AJAX/index.php">AJAX Demo</a></li>
	  </li> 
    </ul> 
  </div> 
  <div class="relatedLinks"> 
    <h3>Links</h3> 
    <ul> 
      <li><a href="http://www.acunetix.com">Security art</a></li> 
	  <li><a href="https://www.acunetix.com/vulnerability-scanner/php-security-scanner/">PHP scanner</a></li>
	  <li><a href="https://www.acunetix.com/blog/articles/prevent-sql-injection-vulnerabilities-in-php-applications/">PHP vuln help</a></li>
	  <li><a href="http://www.eclectasy.com/Fractal-Explorer/index.html">Fractal Explorer</a></li> 
    </ul> 
  </div> 
  <div id="advert"> 
    <p>
      <object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000" codebase="http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=6,0,29,0" width="107" height="66">
        <param name="movie" value="Flash/add.swf">
        <param name=quality value=high>
        <embed src="Flash/add.swf" quality=high pluginspage="http://www.macromedia.com/shockwave/download/index.cgi?P1_Prod_Version=ShockwaveFlash" type="application/x-shockwave-flash" width="107" height="66"></embed>
      </object>
    </p>
  </div> 
</div> 

<!--end navbar --> 
<div id="siteInfo">  <a href="http://www.acunetix.com">About Us</a> | <a href="privacy.php">Privacy Policy</a> | <a href="mailto:wvs@acunetix.com">Contact Us</a> | &copy;2019
  Acunetix Ltd 
</div> 
<br> 
<div style="background-color:lightgray;width:100%;text-align:center;font-size:12px;padding:1px">
<p style="padding-left:5%;padding-right:5%"><b>Warning</b>: This is not a real shop. This is an example PHP application, which is intentionally vulnerable to web attacks. It is intended to help you test Acunetix. It also helps you understand how developer errors and bad configuration may let someone break into your website. You can use it to test other tools and your manual hacking skills as well. Tip: Look for potential SQL Injections, Cross-site Scripting (XSS), and Cross-site Request Forgery (CSRF), and more.</p>
</div>
</div>
</body>
<!-- InstanceEnd --></html>
`
	res := ParseBurpResponse(rawReq, rawRes)
	fmt.Println(res.Status)
	fmt.Println(res.Headers)
	if res.StatusCode != 200 {
		t.Errorf("Error parsing Burp Response")
	}

}
