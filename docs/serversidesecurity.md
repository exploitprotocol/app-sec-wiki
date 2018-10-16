## Remote Code Execution

### Learning

* [Code Injection - OWASP](https://www.owasp.org/index.php/Code_Injection)
* [Command Injection - OWASP](https://www.owasp.org/index.php/Command_Injection)
* [Testing for Command Injection (OTG-INPVAL-013) - OWASP](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013))
* [Testing for Remote File Inclusion - OWASP](https://www.owasp.org/index.php/Testing_for_Remote_File_Inclusion)

### Writeups

* [Artsploit: [demo.paypal.com] Node.js code injection (RCE)](https://artsploit.blogspot.com/2016/08/pprce2.html)
* [Nodejs RCE and a simple reverse shell ](https://ibreak.software/2016/08/nodejs-rce-and-a-simple-reverse-shell/)
* [Pivoting from blind SSRF to RCE with HashiCorp Consul](http://www.kernelpicnic.net/2017/05/29/Pivoting-from-blind-SSRF-to-RCE-with-Hashicorp-Consul.html)
* [Remote Code Execution (RCE) on Microsoft's 'signout.live.com'](http://www.kernelpicnic.net/2016/07/24/Microsoft-signout.live.com-Remote-Code-Execution-Write-Up.html)
* [How we broke PHP, hacked Pornhub and earned $20,000 | Bug Bounties - Evonide](https://www.evonide.com/how-we-broke-php-hacked-pornhub-and-earned-20000-dollar/)
* [Modern Alchemy: Turning XSS into RCE · Doyensec's Blog](https://blog.doyensec.com/2017/08/03/electron-framework-security.html)
* [Electron Security Checklist](https://www.blackhat.com/docs/us-17/thursday/us-17-Carettoni-Electronegativity-A-Study-Of-Electron-Security-wp.pdf)
* [Traversing the Path to RCE – ∞ Growing Web Security Blog](https://hawkinsecurity.com/2018/08/27/traversing-the-path-to-rce/)
* [Upgrade from LFI to RCE via PHP Sessions – RCE Security](https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/)
* [Server-Side Spreadsheet Injection - Formula Injection to Remote Code Execution - Bishop Fox](https://www.bishopfox.com/blog/2018/06/server-side-spreadsheet-injections/)
* [Minded Security Blog: RCE in Oracle NetBeans Opensource Plugins: PrimeFaces 5.x Expression Language Injection](https://blog.mindedsecurity.com/2016/02/rce-in-oracle-netbeans-opensource.html)
* [What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability.](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#background)
* [XSS to RCE in Atlassian Hipchat](https://maustin.net/2015/11/12/hipchat_rce.html)
* [Facebook's ImageTragick Remote Code Execution](https://4lemon.ru/2017-01-17_facebook_imagetragick_remote_code_execution.html)
* [Modern Alchemy: Turning XSS into RCE · Doyensec's Blog](https://blog.doyensec.com/2017/08/03/electron-framework-security.html)
* [From Markdown to RCE in Atom](https://statuscode.ch/2017/11/from-markdown-to-rce-in-atom/)
* [Exploiting Electron RCE in Exodus wallet – Hacker Noon](https://hackernoon.com/exploiting-electron-rce-in-exodus-wallet-d9e6db13c374)
* [$36k Google App Engine RCE - Ezequiel Pereira](https://sites.google.com/site/testsitehacking/-36k-google-app-engine-rce)
* [Orange: How I Chained 4 Bugs(Features?) into RCE on Amazon Collaboration System](http://blog.orange.tw/2018/08/how-i-chained-4-bugs-features-into-rce-on-amazon.html)
* [#135072 RCE in profile picture upload](https://hackerone.com/reports/135072)
* [Trello bug bounty: Access server's files using ImageTragick](https://hethical.io/trello-bug-bounty-access-servers-files-using-imagetragick/)
* [How I Hacked Facebook, and Found Someone's Backdoor Script | DEVCORE](https://devco.re/blog/2016/04/21/how-I-hacked-facebook-and-found-someones-backdoor-script-eng-ver/)
* [#125980 uber.com may RCE by Flask Jinja2 Template Injection](https://hackerone.com/reports/125980)
* [#134738 WordPress SOME bug in plupload.flash.swf leading to RCE](https://hackerone.com/reports/134738)
* [EBAY.COM: RCE USING CCS](https://secalert.net/#ebay-rce-ccs)
* [Airbnb – Ruby on Rails String Interpolation led to Remote Code Execution | Brett Buerhaus](https://buer.haus/2017/03/13/airbnb-ruby-on-rails-string-interpolation-led-to-remote-code-execution/)
* [#206227 Remote Code Execution on Git.imgur-dev.com](https://hackerone.com/reports/206227)
* [#212696 RCE by command line argument injection to `gm convert` in `/edit/process?a=crop`](https://hackerone.com/reports/212696)
* [Command injection which got me "6000$" from #Google](http://www.pranav-venkat.com/2016/03/command-injection-which-got-me-6000.html?view=sidebar)
* [Latex to RCE, Private Bug Bounty Program – InfoSec Write-ups – Medium](https://medium.com/bugbountywriteup/latex-to-rce-private-bug-bounty-program-6a0b5b33d26a)
* [Yahoo! RCE via Spring Engine SSTI – ∞ Growing Web Security Blog](https://hawkinsecurity.com/2017/12/13/rce-via-spring-engine-ssti/)

### Tools/Payloads

* [commixproject/commix: Automated All-in-One OS command injection and exploitation tool.](https://github.com/commixproject/commix)
* [PayloadsAllTheThings/Remote commands execution ](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Remote%20commands%20execution)

## SSRF

### Learning

* [Server Side Request Forgery - OWASP](https://www.owasp.org/index.php/Server_Side_Request_Forgery)
* [Server-Side Request Forgery - SSRF Security Testing ](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF)

### Writeups

* [ESEA Server-Side Request Forgery and Querying AWS Meta Data | Brett Buerhaus](https://buer.haus/2016/04/18/esea-server-side-request-forgery-and-querying-aws-meta-data/)
* [Into the Borg – SSRF inside Google production network | OpnSec](https://opnsec.com/2018/07/into-the-borg-ssrf-inside-google-production-network/)
* [A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
* [#115748 SSRF in https://imgur.com/vidgif/url](https://hackerone.com/reports/115748)
* [PHP SSRF Techniques – secjuice™ – Medium](https://medium.com/secjuice/php-ssrf-techniques-9d422cb28d51)
* [#341876 SSRF in Exchange leads to ROOT access in all instances](https://hackerone.com/reports/341876)
* [Escalating XSS in PhantomJS Image Rendering to SSRF/Local-File Read | Brett Buerhaus](https://buer.haus/2017/06/29/escalating-xss-in-phantomjs-image-rendering-to-ssrflocal-file-read/)
* [BugBountyHQ on Twitter: "tip - Open Graph Protocol is a good case for Blind SSRF / Extract of Meta Data. My POC: SSRF in Twitter via a Tweet :) "](https://twitter.com/BugBountyHQ/status/868242771617792000)
* [Ok Google, Give Me All Your Internal DNS Information! – RCE Security](https://www.rcesecurity.com/2017/03/ok-google-give-me-all-your-internal-dns-information/)

### Tools

* [immunIT/XIP: XIP generates a list of IP addresses by applying a set of transformations used to bypass security measures e.g. blacklist filtering, WAF, etc.](https://github.com/immunIT/XIP)
* [C-REMO/Obscure-IP-Obfuscator: Simple script you can use to convert and obscure any IP address of any host.](https://github.com/C-REMO/Obscure-IP-Obfuscator)
* [tarunkant/Gopherus: This tool generates gopher link for exploiting SSRF and gaining RCE in various servers](https://github.com/tarunkant/Gopherus)
* [blazeinfosec/ssrf-ntlm: Proof of concept written in Python to show that in some situations a SSRF vulnerability can be used to steal NTLMv1/v2 hashes.](https://github.com/blazeinfosec/ssrf-ntlm)
* [PayloadsAllTheThings/SSRF injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SSRF%20injection)

### Cheatsheet/Payloads

* [SSRF bible. Cheatsheet ](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit)
* [SSRF Tips | xl7dev](http://blog.safebuff.com/2016/07/03/SSRF-Tips/)
* [Cloud Metadata Dictionary useful for SSRF Testing](https://gist.github.com/BuffaloWill/fa96693af67e3a3dd3fb)
* [cujanovic/SSRF-Testing: SSRF (Server Side Request Forgery) testing resources](https://github.com/cujanovic/SSRF-Testing/)

## XXE

### Learning

* [XML Vulnerabilities and Attacks cheatsheet](https://gist.github.com/mgeeky/4f726d3b374f0a34267d4f19c9004870)
* [XXE](https://phonexicum.github.io/infosec/xxe.html)
* [XPATH Injection - OWASP](https://www.owasp.org/index.php/XPATH_Injection)
* [Top 10-2017 A4-XML External Entities (XXE) - OWASP](https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_(XXE))
* [XML Security Cheat Sheet - OWASP](https://www.owasp.org/index.php/XML_Security_Cheat_Sheet)
* [XML Parser Evaluation ](https://web-in-security.blogspot.com/2016/03/xml-parser-evaluation.html)
* [DTD Cheat Sheet](https://web-in-security.blogspot.com/2016/03/xxe-cheat-sheet.html)
* [Security Implications of DTD Attacks Against a Wide Range of XML Parsers](https://www.nds.rub.de/media/nds/arbeiten/2015/11/04/spaeth-dtd_attacks.pdf)
* [XXE Cheatsheet – XML External Entity Injection](https://www.gracefulsecurity.com/xxe-cheatsheet/)
* [Generic XXE Detection](http://christian-schneider.net/GenericXxeDetection.html#main)
* [Exploitation: XML External Entity (XXE) Injection](https://depthsecurity.com/blog/exploitation-xml-external-entity-xxe-injection)
* [Payload All The Things XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20injection)
* [XML Vulnerabilities and Attacks cheatsheet](https://gist.github.com/mgeeky/4f726d3b374f0a34267d4f19c9004870)

### Writeups

* [h3xStream's blog: Identifying Xml eXternal Entity vulnerability (XXE)](https://blog.h3xstream.com/2014/06/identifying-xml-external-entity.html)
* [XML Out-of-Band Data Retrival](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf)
* [@ONsec_Lab: XXE OOB exploitation at Java 1.7+](http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html)
* [XML external entity injection explanation and exploitation](https://www.exploit-db.com/docs/english/45374-xml-external-entity-injection---explanation-and-exploitation.pdf)
* [XSLT Server Side Injection Attacks | Context Information Security EN](https://www.contextis.com/en/blog/xslt-server-side-injection-attacks)
* [My "Public Evernote": 0day writeup: XXE in uber.com](https://httpsonly.blogspot.com/2017/01/0day-writeup-xxe-in-ubercom.html)
* [XXE at Bol.com – Jonathan Bouman – Medium](https://medium.com/@jonathanbouman/xxe-at-bol-com-7d331186de54)
* [Coalfire - How I Found CVE-2018-8819: Out-of-Band (OOB) XXE in WebCTRL](https://www.coalfire.com/The-Coalfire-Blog/June-2018/How-I-Found-CVE-2018-8819-Out-of-Band-(OOB)-XXE?feed=blogs)

### Cheatsheets/Payloads

* [XXE Payloads](https://gist.github.com/staaldraad/01415b990939494879b4)
* [DTD Cheat Sheet](https://web-in-security.blogspot.com/2016/03/xxe-cheat-sheet.html)
* [Out of Band Exploitation (OOB) CheatSheet ](https://www.notsosecure.com/oob-exploitation-cheatsheet/)
* [XXE_Payloads | xl7dev](http://blog.safebuff.com/2016/03/30/XXE-Payloads/)
* [XML Vulnerabilities and Attacks cheatsheet](https://gist.github.com/mgeeky/4f726d3b374f0a34267d4f19c9004870)

### Tools

* [staaldraad/xxeserv: A mini webserver with FTP support for XXE payloads](https://github.com/staaldraad/xxeserv)
* [enjoiz/XXEinjector: Tool for automatic exploitation of XXE vulnerability using direct and different out of band methods.](https://github.com/enjoiz/XXEinjector)
* [BuffaloWill/oxml_xxe: A tool for embedding XXE/XML exploits into different filetypes](https://github.com/BuffaloWill/oxml_xxe)
* [TheTwitchy/xxer: A blind XXE injection callback handler. Uses HTTP and FTP to extract information. Originally written in Ruby by ONsec-Lab.](https://github.com/TheTwitchy/xxer)

## Local File Inclusion

### Learning

* [Testing for Local File Inclusion - OWASP](https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion)
* [Testing Directory traversal/file include (OTG-AUTHZ-001) - OWASP](https://www.owasp.org/index.php/Testing_Directory_traversal/file_include_(OTG-AUTHZ-001))
* [Using php://filter for local file inclusion](https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/)
* [Upgrade from LFI to RCE via PHP Sessions](https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/)
* [LFI Cheat Sheet](https://highon.coffee/blog/lfi-cheat-sheet/)
* [Directory Traversal, File Inclusion, and The Proc File System](https://blog.netspi.com/directory-traversal-file-inclusion-proc-file-system/)
* [LFI to shell – exploiting Apache access log](https://roguecod3r.wordpress.com/2014/03/17/lfi-to-shell-exploiting-apache-access-log/)
* [Exploiting PHP File Inclusion – Overview](https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/)

### Writeups

* [One Cloud-based Local File Inclusion = Many Companies affected](https://panchocosil.blogspot.com/2017/05/one-cloud-based-local-file-inclusion.html)
* [Local file inclusion at IKEA.com – Jonathan Bouman – Medium](https://medium.com/@jonathanbouman/local-file-inclusion-at-ikea-com-e695ed64d82f)
* [One Cloud-based Local File Inclusion = Many Companies affected](https://panchocosil.blogspot.com/2017/05/one-cloud-based-local-file-inclusion.html)
* [Josip Franjković - archived security blog: Reading local files from Facebook's server (fixed)](https://josipfranjkovic.blogspot.com/2014/12/reading-local-files-from-facebooks.html)
* [#213558 Arbitrary Local-File Read from Admin - Restore From Backup due to Symlinks](https://hackerone.com/reports/213558)

### Cheatsheets/Payloads

* [LFI Cheat Sheet](https://highon.coffee/blog/lfi-cheat-sheet/)
* [PayloadsAllTheThings/File Inclusion - Path Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion%20-%20Path%20Traversal)

## SQL Injection

### Learning

* [SQLBolt - Learn SQL - Introduction to SQL](https://sqlbolt.com/)
* [SQL Injection - OWASP](https://www.owasp.org/index.php/SQL_Injection)
* [Blind SQL Injection - OWASP](https://www.owasp.org/index.php/Blind_SQL_Injection)
* [NetSPI SQL Injection Wiki](https://sqlwiki.netspi.com/)
* [Testing for SQL Injection (OTG-INPVAL-005) - OWASP](https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005))
* [SQL Injection Bypassing WAF - OWASP](https://www.owasp.org/index.php/SQL_Injection_Bypassing_WAF)
* [SQLInjection.net](http://www.sqlinjection.net/)
* [Exploiting A Tricky SQL Injection With sqlmap](http://pentestmonkey.net/blog/exploiting-a-tricky-sql-injection-with-sqlmap)
* [SQLMap Tamper Scripts (SQL Injection and WAF bypass) Tips](https://medium.com/@drag0n/sqlmap-tamper-scripts-sql-injection-and-waf-bypass-c5a3f5764cb3)
* [SQLMap Tamper Scripts (SQL Injection and WAF bypass)](https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423)
* [SQLi Without Quotes](https://eternalnoobs.com/sqli-without-quotes/)  

### Writeups

* [Time based CAPTCHA protected SQL injection through SOAP-webservice](https://www.slideshare.net/fransrosen/time-based-captcha-protected-sql-injection-through-soapwebservice)
* [Manual SQL injection discovery tips](https://gerbenjavado.com/manual-sql-injection-discovery-tips/)
* [Tesla Motors blind SQL injection - Bitquark](https://bitquark.co.uk/blog/2014/02/23/tesla_motors_blind_sql_injection)
* [Blind SQL Inejction [Hootsuite] • Abdullah Hussam](https://ahussam.me/Blind-sqli-Hootsuite/)
* [#150156 SQL Injection on sctrack.email.uber.com.cn](https://hackerone.com/reports/150156)
* [Exploiting a Boolean Based SQL Injection using Burp Suite Intruder – i break software](https://ibreak.software/2017/12/exploiting-a-boolean-based-sql-injection-using-burp-suite-intruder/)
* [Beyond SQLi: Obfuscate and Bypass](https://www.exploit-db.com/papers/17934/)
* [Orange: GitHub Enterprise SQL Injection](http://blog.orange.tw/2017/01/bug-bounty-github-enterprise-sql-injection.html)
* [Anatomy of a Hack: SQLi to Enterprise Admin](https://www.notsosecure.com/anatomy-of-a-hack-sqli-to-enterprise-admin/)

### Cheatsheet/Payloads

* [SQL Injection Cheat Sheet | Netsparker](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
* [The SQL Injection Knowledge Base](https://websec.ca/kb/sql_injection)
* [PayloadsAllTheThings/SQL injection ](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20injection)
### Tools

* [sqlmapproject/sqlmap: Automatic SQL injection and database takeover tool](https://github.com/sqlmapproject/sqlmap)
* [Neohapsis/bbqsql: Blind SQL Injection Exploitation Tool](https://github.com/Neohapsis/bbqsql)
* [ron190/jsql-injection: jSQL Injection is a Java application for automatic SQL database injection.](https://github.com/ron190/jsql-injection)

## Json Web Token(JWT)

* [Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
* [JWT - OWASP](https://www.owasp.org/index.php/REST_Security_Cheat_Sheet#JWT)
* [Common JWT security vulnerabilities and how to avoid them | Connect2id](https://connect2id.com/products/nimbus-jose-jwt/vulnerabilities)
* [JSON Web Token (JWT) Cheat Sheet for Java - OWASP](https://www.owasp.org/index.php/JSON_Web_Token_(JWT)_Cheat_Sheet_for_Java)
* [How to Hack a Weak JWT Implementation with a Timing Attack](https://hackernoon.com/can-timing-attack-be-a-practical-security-threat-on-jwt-signature-ba3c8340dea9)
* [Stop using JWT for sessions](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/)
* [Stop using JWT for sessions, part 2: Why your solution doesn't work](http://cryto.net/~joepie91/blog/2016/06/19/stop-using-jwt-for-sessions-part-2-why-your-solution-doesnt-work/)
* [Crafting your way through JSON Web Tokens](https://www.notsosecure.com/crafting-way-json-web-tokens/)
* [JWT Hacking 101](https://trustfoundry.net/jwt-hacking-101/)

### Writeups

* [How I got access to millions of [redacted] accounts - Bitquark](https://bitquark.co.uk/blog/2016/02/09/how_i_got_access_to_millions_of_redacted_accounts)
* [Hacking JSON Web Tokens](https://blog.websecurify.com/2017/02/hacking-json-web-tokens.html)

### Tools

* [ticarpi/jwt_tool: A toolkit for testing, tweaking and cracking JSON Web Tokens](https://github.com/ticarpi/jwt_tool)
* [brendan-rius/c-jwt-cracker: JWT brute force cracker written in C](https://github.com/brendan-rius/c-jwt-cracker)
* [lmammino/jwt-cracker: Simple HS256 JWT token brute force cracker](https://github.com/lmammino/jwt-cracker)
* [lmammino/distributed-jwt-cracker: An experimental distributed JWT token cracker built using Node.js and ZeroMQ](https://github.com/lmammino/distributed-jwt-cracker)
* [AresS31/jwtcat: JSON Web Token (JWT) cracker.](https://github.com/AresS31/jwtcat)

## HQL Injection

### Learning

* [h3xStream's blog: HQL for pentesters](https://blog.h3xstream.com/2014/02/hql-for-pentesters.html)

### Writeups

* [ORM2Pwn: Exploiting injections in Hibernate ORM](http://2015.zeronights.ru/assets/files/36-Egorov-Soldatov.pdf)
* [Hibernate HQL - Hibernate Query Language Examples - - HowToDoInJava](https://howtodoinjava.com/hibernate/complete-hibernate-query-language-hql-tutorial/#select_operation)
* [Blind HQL Injection in REST API using H2 dbms - PaulSec's blog](https://paulsec.github.io/blog/2014/05/05/blind-hql-injection-in-rest-api-using-h2-dbms/)

### Tools

* [PaulSec/HQLmap: HQLmap, Automatic tool to exploit HQL injections](https://github.com/PaulSec/HQLmap)

## Mongo DB Injection

### Learning

* [Testing for NoSQL injection - OWASP](https://www.owasp.org/index.php/Testing_for_NoSQL_injection)
* [Attacking MongoDB](http://blog.ptsecurity.com/2012/11/attacking-mongodb.html)

### Writeups

* [Hacking NodeJS and MongoDB](https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html)
* [NOSQL INJECTION: FUN WITH OBJECTS AND ARRAYS](https://www.owasp.org/images/e/ed/GOD16-NOSQL.pdf)

### For developers

* [Avoiding MongoDB hash-injection attacks](https://cirw.in/blog/hash-injection)

### Tools/Payloads

* [codingo/NoSQLMap: Automated NoSQL database enumeration and web application exploitation tool.](https://github.com/codingo/NoSQLMap)
* [PayloadsAllTheThings/NoSQL injection ](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20injection)

## Race Conditions

### Learning

* [Testing for Race Conditions (OWASP-AT-010) - OWASP](https://www.owasp.org/index.php/Testing_for_Race_Conditions_(OWASP-AT-010))

### Writeups

* [Race conditions on the web - Josip Franjković](https://www.josipfranjkovic.com/blog/race-conditions-on-web)
* [Exploiting and Protecting Against Race Conditions](https://lightningsecurity.io/blog/race-conditions/)
* [Josip Franjković - archived security blog: Race conditions on Facebook, DigitalOcean and others (fixed)](https://josipfranjkovic.blogspot.com/2015/04/race-conditions-on-facebook.html)
* [Exploiting an unknown vulnerability - Learn, Build & Break](https://abhibundela.com/2018/09/25/exploiting-an-unknown-vulnerability/)

### Tools

* [insp3ctre/race-the-web: Tests for race conditions in web applications. Includes a RESTful API to integrate into a continuous integration pipeline.](https://github.com/insp3ctre/race-the-web)

## Bruteforce

### Learning

* [Brute force attack - OWASP](https://www.owasp.org/index.php/Brute_force_attack)
* [Testing for Brute Force (OWASP-AT-004) - OWASP](https://www.owasp.org/index.php/Testing_for_Brute_Force_(OWASP-AT-004))

### Writeups

* [How I could have hacked all Facebook accounts](http://www.anandpraka.sh/2016/03/how-i-could-have-hacked-your-facebook.html)
* [#144616 Brute-Forcing invite codes in partners.uber.com](https://hackerone.com/reports/144616)
* [#125505 Possibility to brute force invite codes in riders.uber.com](https://hackerone.com/reports/125505)
* [InstaBrute: Two Ways to Brute-force Instagram Account Credentials – Arne Swinnen's Security Blog](https://www.arneswinnen.net/2016/05/instabrute-two-ways-to-brute-force-instagram-account-credentials/)
* [How I Could Compromise 4% (Locked) Instagram Accounts – Arne Swinnen's Security Blog](https://www.arneswinnen.net/2016/03/how-i-could-compromise-4-locked-instagram-accounts/)
* [#127844 Web Authentication Endpoint Credentials Brute-Force Vulnerability](https://hackerone.com/reports/127844)
* [Cross-origin brute-forcing of Github SAML and 2FA recovery codes](http://blog.intothesymmetry.com/2017/05/cross-origin-brute-forcing-of-saml-and.html)

## Host Header Injection

### Learning

* [Cache Poisoning - OWASP](https://www.owasp.org/index.php/Cache_Poisoning)
* [What Is a Host Header Attack? ](https://dzone.com/articles/what-is-a-host-header-attack)

### Writeups

* [Combining host header injection and lax host parsing serving malicious data](https://labs.detectify.com/2016/10/24/combining-host-header-injection-and-lax-host-parsing-serving-malicious-data/)
* [Internet Explorer has a URL problem](https://blog.innerht.ml/internet-explorer-has-a-url-problem/)

## Web Cache Deception

* [Omer Gil: Web Cache Deception Attack](https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html)
* [#260697 CSRF-tokens on pages without no-cache headers, resulting in ATO when using CloudFlare proxy (Web Cache Deception)](https://hackerone.com/reports/260697)
* [PayloadsAllTheThings/Web cache deception ](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20cache%20deception)

## API Security

* [REST Security Cheat Sheet - OWASP](https://www.owasp.org/index.php/REST_Security_Cheat_Sheet)
* [shieldfy/API-Security-Checklist: Checklist of the most important security countermeasures when designing, testing, and releasing your API](https://github.com/shieldfy/API-Security-Checklist)
* [An interesting Google vulnerability that got me 3133.7 reward. | Security Down!](http://www.sec-down.com/wordpress/?p=809)

## Oauth Security

* [Top X OAuth 2 Hacks (OAuth Implementation vulnerabilities)](https://www.owasp.org/images/6/61/20151215-Top_X_OAuth_2_Hacks-asanso.pdf)
* [Top 10 OAuth 2 Implementation Vulnerabilities](http://blog.intothesymmetry.com/2015/12/top-10-oauth-2-implementation.html)
* [OAuth 2.0 Security Best Current Practice](https://www.ietf.org/id/draft-ietf-oauth-security-topics-07.txt)
* [Bug Bounty : Account Takeover Vulnerability POC](http://blog.rakeshmane.com/2016/09/bug-bounty-account-takeover.html)
* [All your Paypal OAuth tokens belong to me - localhost for the win](http://blog.intothesymmetry.com/2016/11/all-your-paypal-tokens-belong-to-me.html)

### Cheatsheets/Payloads

* [Oauth Security Cheatsheet by Sakurity](https://sakurity.com/oauth)
* [PayloadsAllTheThings/OAuth ](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth)

## GraphQL Security

* [Pete Corey - GraphQL NoSQL Injection Through JSON Types](http://www.petecorey.com/blog/2017/06/12/graphql-nosql-injection-through-json-types/)
* [Security Points to Consider Before Implementing GraphQL | Nordic APIs |](https://nordicapis.com/security-points-to-consider-before-implementing-graphql/)
* [In graph we trust: Microservices, GraphQL and security challenges](https://www.slideshare.net/secfigo/in-graph-we-trust-microservices-graphql-and-security-challenges)
* [Looting GraphQL Endpoints for Fun and Profit | Raz0r.name — Web Application Security](https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/)
* [Pete Corey - GraphQL NoSQL Injection Through JSON Types](http://www.petecorey.com/blog/2017/06/12/graphql-nosql-injection-through-json-types/)
* [Discovering GraphQL endpoints and SQLi vulnerabilities](https://medium.com/@localh0t/discovering-graphql-endpoints-and-sqli-vulnerabilities-5d39f26cea2e)
* [GraphQL abuse: Bypass account level permissions through parameter smuggling](https://labs.detectify.com/2018/03/14/graphql-abuse/)
* [A Facebook GraphQL crash course](https://www.facebook.com/notes/phwd/a-facebook-graphql-crash-course/1189337427822946)
* [#291531 Introspection query leaks sensitive graphql system information.](https://hackerone.com/reports/291531)

### Tools

* [doyensec/graph-ql: GraphQL Security Research Material](https://github.com/doyensec/graph-ql)

## Java Deserilization

### Learning

* [Deserialization of untrusted data - OWASP](https://www.owasp.org/index.php/Deserialization_of_untrusted_data)
* [Deserialization Cheat Sheet - OWASP](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [Top 10-2017 A8-Insecure Deserialization - OWASP](https://www.owasp.org/index.php/Top_10-2017_A8-Insecure_Deserialization)

### Writeups

* [Blind Java Deserialization Vulnerability - Commons Gadgets](https://deadcode.me/blog/2016/09/02/Blind-Java-Deserialization-Commons-Gadgets.html)
* [Blind Java Deserialization - Part II - exploitation rev 2](https://deadcode.me/blog/2016/09/18/Blind-Java-Deserialization-Part-II.html)
* [OWASP SD: Deserialize My Shorts: Or How I Learned To Start Worrying a…](https://www.slideshare.net/frohoff1/deserialize-my-shorts-or-how-i-learned-to-start-worrying-and-hate-java-object-deserialization)
* [What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability.](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/)
* [Coalfire - Coalfire Blog - Exploiting Blind Java Deserialization with Burp and Ysoserial](https://www.coalfire.com/The-Coalfire-Blog/Sept-2018/Exploiting-Blind-Java-Deserialization?feed=blogs)
* [Artsploit: [manager.paypal.com] Remote Code Execution Vulnerability](https://artsploit.blogspot.com/2016/01/paypal-rce.html)
* [Case Study – New Way To Exploit Java Deserialization Vulnerability](http://varutra.com/blog/?p=1559)
* [Exploiting Java Deserialization Via JBoss – Bug Bounty Findings by Meals](https://seanmelia.wordpress.com/2016/07/22/exploiting-java-deserialization-via-jboss/)

### Tools

* [foxglovesec/JavaUnserializeExploits](https://github.com/foxglovesec/JavaUnserializeExploits)
* [joaomatosf/jexboss: JexBoss: Jboss (and Java Deserialization Vulnerabilities) verify and EXploitation Tool](https://github.com/joaomatosf/jexboss)
* [Coalfire-Research/java-deserialization-exploits: A collection of curated Java Deserialization Exploits](https://github.com/Coalfire-Research/java-deserialization-exploits)
* [frohoff/ysoserial: A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization.](https://github.com/frohoff/ysoserial)
* [JackOfMostTrades/gadgetinspector: A byte code analyzer for finding deserialization gadget chains in Java applications](https://github.com/JackOfMostTrades/gadgetinspector)

### Cheatsheets/Payloads

* [GrrrDog/Java-Deserialization-Cheat-Sheet: The cheat sheet about Java Deserialization vulnerabilities](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
* [PayloadsAllTheThings/Java Deserialization ](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Java%20Deserialization)

## Authentication Bypass

### Learning

* [Testing for Bypassing Authentication Schema (OTG-AUTHN-004) - OWASP](https://www.owasp.org/index.php/Testing_for_Bypassing_Authentication_Schema_(OTG-AUTHN-004))
* [Top 10-2017 A2-Broken Authentication - OWASP](https://www.owasp.org/index.php/Top_10-2017_A2-Broken_Authentication)
* [Authentication Cheat Sheet - OWASP](https://www.owasp.org/index.php/Authentication_Cheat_Sheet)
* [Testing for HTTP Verb Tampering (OTG-INPVAL-003) - OWASP](https://www.owasp.org/index.php/Testing_for_HTTP_Verb_Tampering_(OTG-INPVAL-003))
* [GoogleMeetRoulette: Joining random meetings - Martin Vigo](https://www.martinvigo.com/googlemeetroulette/)

### Writeups

* [#172137 Authentication bypass on sso.ubnt.com via subdomain takeover of ping.ubnt.com](https://hackerone.com/reports/172137)
* [InstaBrute: Two Ways to Brute-force Instagram Account Credentials – Arne Swinnen's Security Blog](https://www.arneswinnen.net/2016/05/instabrute-two-ways-to-brute-force-instagram-account-credentials/)
* [Uber Hacking: How we found out who you are, where you are and where you went! | INTEGRITY Labs](https://labs.integrity.pt/articles/uber-hacking-how-we-found-out-who-you-are-where-you-are-and-where-you-went/)
* [Bypassing Firebase authorization to create custom goo.gl subdomains - Thomas Orlita's blog](https://blog.thomasorlita.cz/vulns/bypassing-firebase-authorization-to-create-custom-goo-gl-subdomains/)
* [Taking over Facebook accounts using Free Basics partner portal - Josip Franjković](https://www.josipfranjkovic.com/blog/facebook-partners-portal-account-takeover)
* [Bypassing Google Authentication on Periscope's Administration Panel – Jack](https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/)
* [Using a GitHub app to escalate to an organization owner for a $10,000 bounty](https://medium.com/@cachemoney/using-a-github-app-to-escalate-to-an-organization-owner-for-a-10-000-bounty-4ec307168631)
* [Hijacking a Facebook Account with SMS – Jack](https://whitton.io/articles/hijacking-a-facebook-account-with-sms/)
* [Django Privilege Escalation – Zero To Superuser](https://seanmelia.files.wordpress.com/2017/06/django-privilege-escalation-e28093-zero-to-superuser.pdf)
* [Bypassing Google’s authentication to access their Internal Admin panels. — Vishnu Prasad P G](https://medium.com/bugbountywriteup/bypassing-googles-fix-to-access-their-internal-admin-panels-12acd3d821e3)
* [How I hacked Google’s bug tracking system itself for $15,600 in bounties](https://medium.freecodecamp.org/messing-with-the-google-buganizer-system-for-15-600-in-bounties-58f86cc9f9a5)
* [Authentication bypass on Uber’s Single Sign-On via subdomain takeover – Arne Swinnen's Security Blog](https://www.arneswinnen.net/2017/06/authentication-bypass-on-ubers-sso-via-subdomain-takeover/)
* [#143717 Change any Uber user's password through /rt/users/passwordless-signup - Account Takeover (critical)](https://hackerone.com/reports/143717)
* [Password Not Provided - Compromising Any Flurry User's Account | Lightning Security](https://lightningsecurity.io/blog/password-not-provided/)
* [Inspect Element leads to Stripe Account Lockout Authentication Bypass | Security and Bug Hunting](https://www.jonbottarini.com/2017/04/03/inspect-element-leads-to-stripe-account-lockout-authentication-bypass/)

## CSV Injection

* [CSV Injection - OWASP](https://www.owasp.org/index.php/CSV_Injection)
* [The Absurdly Underestimated Dangers of CSV Injection](http://georgemauer.net/2017/10/07/csv-injection.html)
* [Everything about the CSV Excel Macro Injection - SecureLayer7](http://blog.securelayer7.net/how-to-perform-csv-excel-macro-injection/)
* [Comma Separated Vulnerabilities ](https://www.contextis.com/en/blog/comma-separated-vulnerabilities)

## Rails Security

* [Rails Security - First part - HackMD](https://hackmd.io/s/SkuTVw5O-)

## Server Side Template Injection

* [Server-Side Includes (SSI) Injection - OWASP](https://www.owasp.org/index.php/Server-Side_Includes_(SSI)_Injection)
* [Server-Side Template Injection | Blog](https://portswigger.net/blog/server-side-template-injection)
* [Server-Side Template Injection:RCE for the modern webapp](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
* [Exploitation of Server Side Template Injection with Craft CMS plugin SEOmatic | Can I Haz Security](http://ha.cker.info/exploitation-of-server-side-template-injection-with-craft-cms-plguin-seomatic/)
* [Exploring SSTI in Flask/Jinja2](https://www.lanmaster53.com/2016/03/09/exploring-ssti-flask-jinja2/)
* [Exploring SSTI in Flask/Jinja2 - Part 2](https://www.lanmaster53.com/2016/03/11/exploring-ssti-flask-jinja2-part-2/)

### Tools

* [epinna/tplmap: Server-Side Template Injection and Code Injection Detection and Exploitation Tool](https://github.com/epinna/tplmap)
* [PayloadsAllTheThings/Server Side Template injections](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20injections)

## WAF Bypass

* [Web Application Firewall (WAF) Evasion Techniques – secjuice™ – Medium](https://medium.com/secjuice/waf-evasion-techniques-718026d693d8)
* [Web Application Firewall (WAF) Evasion Techniques #2](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [Web Application Firewall (WAF) Evasion Techniques #3](https://www.secjuice.com/web-application-firewall-waf-evasion/)
* [Airbnb – When Bypassing JSON Encoding, XSS Filter, WAF, CSP, and Auditor turns into Eight Vulnerabilities | Brett Buerhaus](https://buer.haus/2017/03/08/airbnb-when-bypassing-json-encoding-xss-filter-waf-csp-and-auditor-turns-into-eight-vulnerabilities/)
* [How to bypass libinjection in many WAF/NGWAF – Ivan Novikov – Medium](https://medium.com/@d0znpp/how-to-bypass-libinjection-in-many-waf-ngwaf-1e2513453c0f)

## WebHooks Security

* [Bypassing Payments Using Webhooks | Lightning Security](https://lightningsecurity.io/blog/bypassing-payments-using-webhooks/)

## SAML

* [Bypassing SAML 2.0 SSO with XML Signature Attacks • Aura Information Security Research Blog](https://research.aurainfosec.io/bypassing-saml20-SSO/)
* [On Breaking SAML: Be Whoever You Want to Be | USENIX](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky)
* [Attacking SSO: Common SAML Vulnerabilities and Ways to Find Them](https://blog.netspi.com/attacking-sso-common-saml-vulnerabilities-ways-find/)
* [Economy of mechanism – The road to hell is paved with SAML Assertions](http://www.economyofmechanism.com/office365-authbypass.html#office365-authbypass)
* [Economy of mechanism – The road to your codebase is paved with forged assertions](http://www.economyofmechanism.com/github-saml.html)

## Python Related

* [Exploiting Python Deserialization Vulnerabilities](https://crowdshield.com/blog.php?name=exploiting-python-deserialization-vulnerabilities)
* [Explaining and exploiting deserialization vulnerability with Python (EN)](https://dan.lousqui.fr/explaining-and-exploiting-deserialization-vulnerability-with-python-en.html)
* [Python format string vulnerability (Django as an example)](https://www.leavesongs.com/PENETRATION/python-string-format-vulnerability.html)
* [Exploiting Python PIL Module Command Execution Vulnerability](http://docs.ioin.in/writeup/github.com/_neargle_PIL_RCE_By_GhostButt/index.html)
* [SethSec: Exploiting Python Code Injection in Web Applications](https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html)
* [Jinja2 template injection filter bypasses | Sebastian Neef - 0day.work](https://0day.work/jinja2-template-injection-filter-bypasses/)

### Tools

* [python-security/pyt: A Static Analysis Tool for Detecting Security Vulnerabilities in Python Web Applications](https://github.com/python-security/pyt)

## NodeJS Related

* [Pentesting Node.js Application : Nodejs Application Security](http://www.websecgeeks.com/2017/04/pentesting-nodejs-application-nodejs.html)
* [SethSec: Exploiting Server Side Request Forgery on a Node/Express Application (hosted on Amazon EC2)](https://sethsec.blogspot.com/2015/12/exploiting-server-side-request-forgery.html)

### Tools

* [ajinabraham/NodeJsScan: NodeJsScan is a static security code scanner for Node.js applications.](https://github.com/ajinabraham/NodeJsScan)

## Php Related

* [Talking about php deserialization vulnerability](https://chybeta.github.io/2017/06/17/%E6%B5%85%E8%B0%88php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/)
* [PayloadsAllTheThings/PHP serialization ](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/PHP%20serialization)

## Application Logic

* [Business logic vulnerability - OWASP](https://www.owasp.org/index.php/Business_logic_vulnerability)
* [Testing for business logic - OWASP](https://www.owasp.org/index.php/Testing_for_business_logic)
* [Google Exploit - Steal Account Login Email Addresses - Tom Anthony](http://www.tomanthony.co.uk/blog/google-exploit-steal-login-email-addresses/)
* [How re-signing up for an account lead to account takeover](https://medium.com/@zseano/how-re-signing-up-for-an-account-lead-to-account-takeover-3a63a628fd9f)

## Insecure Direct Object Reference(IDOR)

### Learning

* [Top 10 2013-A4-Insecure Direct Object References - OWASP](https://www.owasp.org/index.php/Top_10_2013-A4-Insecure_Direct_Object_References)
* [Testing for Insecure Direct Object References (OTG-AUTHZ-004) - OWASP](https://www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004))
* [How-To: Find IDOR (Insecure Direct Object Reference) Vulnerabilities](https://www.bugcrowd.com/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/)

### Writeups

* [Uber Hacking: How we found out who you are, where you are and where you went! | INTEGRITY Labs](https://labs.integrity.pt/articles/uber-hacking-how-we-found-out-who-you-are-where-you-are-and-where-you-went/)
* [Gsuite Hangouts Chat 5k IDOR](https://secreltyhiddenwriteups.blogspot.com/2018/07/gsuite-hangouts-chat-5k-idor.html)
* [Facebook's Bug - Delete any video from Facebook](https://pranavhivarekar.in/2016/06/23/facebooks-bug-delete-any-video-from-facebook/)
* [Hacking Facebook's Legacy API, Part 1: Making Calls on Behalf of Any User](https://stephensclafani.com/2014/07/08/hacking-facebooks-legacy-api-part-1-making-calls-on-behalf-of-any-user/)
* [Hacking Facebook's Legacy API, Part 2: Stealing User Sessions](https://stephensclafani.com/2014/07/29/hacking-facebooks-legacy-api-part-2-stealing-user-sessions/)
* [Get as image function pulls any Insights/NRQL data from any New Relic account (IDOR)](https://jonbottarini.com/2018/10/09/get-as-image-function-pulls-any-insights-nrql-data-from-any-new-relic-account-idor/)

## SMTP Injection

* [Testing for IMAP/SMTP Injection (OTG-INPVAL-011) - OWASP](https://www.owasp.org/index.php/Testing_for_IMAP/SMTP_Injection_(OTG-INPVAL-011))
* [Please email me your password](http://blog.jr0ch17.com/2018/Please-email-me-your-password/)

## CRLF Injection

* [CRLF Injection - OWASP](https://www.owasp.org/index.php/CRLF_Injection)
* [Testing for HTTP Splitting/Smuggling (OTG-INPVAL-016) - OWASP](https://www.owasp.org/index.php/Testing_for_HTTP_Splitting/Smuggling_(OTG-INPVAL-016))
* [CRLF Injection / HTTP Response Splitting Explained](https://prakharprasad.com/crlf-injection-http-response-splitting-explained/)
* [Setting arbitrary request headers in Chromium via CRLF injection | MB blog](https://blog.bentkowski.info/2018/06/setting-arbitrary-request-headers-in.html)

### Payloads

* [cujanovic/CRLF-Injection-Payloads: Payloads for CRLF Injection](https://github.com/cujanovic/CRLF-Injection-Payloads/blob/master/CRLF-payloads.txt)
* [PayloadsAllTheThings/CRLF injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20injection)

## Forgot Password Related Vulnerabilities

* [Forgot Password Cheat Sheet - OWASP](https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet)
* [Full account Takeover via reset password function](https://medium.com/@khaled.hassan/full-account-takeover-via-reset-password-function-8b6ef15f346f)

## Smart Contracts Security

* [Decentralized Application Security Project](http://www.dasp.co/index.html)
* [Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
* [ConsenSys/mythril: Mythril OSS: Security analysis tool for Ethereum smart contracts](https://github.com/ConsenSys/mythril)
* [Ethernaut](https://ethernaut.zeppelin.solutions/)
