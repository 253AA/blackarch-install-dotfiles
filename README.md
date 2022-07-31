# blackarch-install-dotfiles
Instalacion y personalizacion de blackarch desde cero

1. Primero estableceremos una conexion a internet, usaremos el siguiente comando de intalacion, solo llegando a el apartado de configuracion de red.
```
blackarch-install
```
2. Despues de tener una conexion a red, instalaremos el siguiente paquete:
```
pacman -S blackarch-keyring
```
3. Hacemos continuar la instalacion con el comando ***blackarch-install***, recuerda instalar todos los entornos de escritorio.
4. Dentro del entorno abre una terminal y escribe el siguiente comando para actualizar el sistema:
```
pacman -Syu
```
5. Despues intalaremos todos los paquetes de blackarch.
```
sudo pacman -S 0d1n 0trace 3proxy 3proxy-win32 42zip a2sv abcd abuse-ssl-bypass-waf acccheck ace aclpwn activedirectoryenum adape-script adenum adfind adfspray adidnsdump ad-ldap-enum admid-pack adminpagefinder admsnmp aesfix aeskeyfind aespipe aesshell afflib aflplusplus afpfs-ng agafi against aggroargs aiengine aimage aiodnsbrute air aircrack-ng airflood airgeddon airopy airoscript airpwn ajpfuzzer albatar allthevhosts altdns amass amber amoco analyzemft analyzepesig androbugs androguard androick android-apktool android-ndk androidpincrack android-sdk androidsniffer android-udev-rules androwarn angr angr-management angrop angr-py2 anontwi antiransom anti-xss apache-users apacket aphopper apkid apkleaks apkstat apkstudio apnbf appmon apt2 aquatone arachni aranea arcane archivebox arduino argon2 argus argus-clients arjun armitage armor armscgen arpalert arpoison arpon arp-scan arpstraw arptools arpwner artillery artlas arybo asleap asp-audit assetfinder astra atear atftp athena-ssl-scanner atlas atscan atstaketools attacksurfacemapper attk aurebeshjs auto-eap automato autonessus autonse autopsy autopwn autorecon autosint autosploit autovpn auto-xor-decryptor avaloniailspy avet avml awsbucketdump aws-extender-cli aws-inventory azazel aztarna backcookie backdoor-apk backdoor-factory backdoorme backdoorppt backfuzz backhack backoori backorifice badkarma badministration bad-pdf bagbak balbuzard bamf-framework bandicoot barf barmie barq base64dump basedomainname bashfuscator bashscan batctl batman-adv batman-alfred bbqsql bbscan bdfproxy bdlogparser bed beebug beef beeswarm beholder belati beleth bettercap bettercap-ui bfac bfbtester bfuzz bgp-md5crack bgrep billcipher binaryninja-demo binaryninja-python bind bindead bindiff binex binflow bing-ip2hosts bing-lfi-rfi bingoo binnavi binproxy binwalk binwally bios_memimage birp bitdump bittwist bkcrack bkhive blackarch-mirrorlist blackbox-scanner blackeye blackhash blacknurse bleah bless bletchley blindelephant blindsql blind-sql-bitshifting blindy blisqy bloodhound bloodhound-python bluebox-ng bluebugger bluediving bluefog blue-hydra bluelog bluepot blueprint blueranger bluescan bluesnarfer bluffy bluphish bluto bmap-tools bmc-tools bob-the-butcher bof-detector bonesi boofuzz boopsuite bopscrk botb bowcaster box-js braa braces brakeman brosec browselist browser-fuzzer brut3k1t brute12 brute-force bruteforce-luks bruteforce-salted-openssl bruteforce-wallet brutemap brutespray brutessh brutex brutexss brutus bsdiff bsqlbf bsqlinjector bss bt_audit btcrack btlejack btproxy-mitm btscanner bulk-extractor bully bunny burpsuite buster buttinsky bvi byepass bypass-firewall-dns-history bytecode-viewer c5scan cachedump cadaver cafebabe cameradar camover camscan canalyzat0r canari cangibrina cansina cantoolz can-utils capfuzz capstone captipper cardpwn carwhisperer casefile catana catnthecanary catphish ccrawldns cdpsnarf cecster centry cero certgraph cewl cflow cfr chainsaw chameleon chameleonmini changeme chankro chaos-client chaosmap chaosreader chapcrack cheat-sh checkiban checksec check-weak-dh-ssh chiasm-shell chipsec chiron chisel chkrootkit chntpw chopshop choronzon chownat chrome-decode chromefreak chromensics chw00t cidr2range cintruder cipherscan ciphertest ciphr cirt-fuzzer cisco5crack cisco7crack cisco-auditing-tool cisco-global-exploiter cisco-ocs cisco-router-config ciscos cisco-scanner cisco-snmp-enumeration cisco-snmp-slap cisco-torch citadel cjexploiter clair clamscanlogparser clash climber cloakify cloud-buster cloudfail cloudflare-enum cloudget cloudlist cloudmare cloudsploit cloudunflare clusterd cminer cmospwd cmseek cms-explorer cms-few cmsfuzz cmsmap cmsscan cmsscanner cnamulator cntlm codeql codetective comission commix commonspeak complemento compp configpush conpot conscan cook cookie-cadger corkscrew corscanner corstest corsy cottontail cowpatty cpfinder cppcheck cpptest cr3dov3r crabstick cracken crackhor crackle crackmapexec crackq crackserver crawlic creak create_ap creddump credmap creds credsniper creepy cribdrag crlf-injector crlfuzz crosslinked crosstool-ng crowbar crozono crunch crypthook cryptonark csrftester ct-exposer ctf-party ctunnel ctypes-sh cuckoo cupp cutycapt cve-api cvechecker cve-search cybercrowl cyberscan cymothoa dagon dalfox damm daredevil darkarmour darkbing darkd0rk3r dark-dork-searcher darkdump darkjumper darkmysqli darkscrape darkspiritz darkstat datajackproxy datasploit davoset davscan davtest dawnscanner dbd dbpwaudit dbusmap dc3dd dcfldd dcrawl ddosify ddrescue de4dot deathstar debinject deblaze decodify deen deepce delldrac delorean demiguise densityscout depant depdep dependency-check depix det detectem detect-it-easy detect-secrets detect-sniffer devaudit device-pharmer dex2jar dexpatcher dff-scanner dfir-ntfs dftimewolf dga-detection dharma dhcdrop dhcpf dhcpig dhcpoptinj didier-stevens-suite dinouml dirb dirble dirbuster dirbuster-ng directorytraversalscan dirhunt dirscanner dirscraper dirsearch dirstalk disitool dislocker dissector distorm dive dizzy dkmc dmde dmg2img dmitry dnmap dns2geoip dns2tcp dnsa dnsbf dnsbrute dnscan dnschef dnscobra dnsdiag dnsdrdos dnsenum dnsfilexfer dnsgoblin dnsgrep dnsmap dnsobserver dns-parallel-prober dnspredict dnsprobe dnspy dnsrecon dns-reverse-proxy dnssearch dnsspider dns-spoof dnsteal dnstracer dnstwist dnsvalidator dnswalk dnsx docem dockerscan domain-analyzer domained domainhunter domain-stats domato domi-owned domlink dontgo403 donut doona doork doozer dorkbot dorkme dorknet dorkscout dotdotpwn dotpeek dpeparser dpscan dr0p1t-framework dracnmap dradis-ce dragon-backdoor dr-checker driftnet drinkme dripcap dripper droopescan drozer drupal-module-enum drupalscan drupwn dscanner dsd dsfs dshell dsjs dsniff dsss dsstore-crawler dsxs d-tect dtp-spoof dublin-traceroute ducktoolkit dumb0 dump1090 dumpacl dumpsmbshare dumpusers dumpzilla duplicut dutas dvcs-ripper dwarf dynamorio eapeak eaphammer eapmd5pass easy-creds easyda easyfuzzer eazy ecfs edb eggshell eigrp-tools eindeutig electric-fence elettra elettra-gui elevate elfkickers elfparser elfutils elidecode elite-proxy-finder email2phonenumber emldump emp3r0r empire enabler encodeshellcode ent enteletaor entropy enum4linux enum4linux-ng enumerate-iam enumerid enumiax enum-shares enyelkm eos epicwebhoneypot eraser erase-registrations eresi erl-matter espionage eternal-scanner etherape etherchange etherflood ettercap evilclippy evilginx evilgrade evilize evillimiter evilmaid evilpdf evil-ssdp evil-winrm evine evtkit exabgp exe2image exescan exitmap expimp-lookup exploit-db exploitdb exploitpack expose exrex extended-ssrf-search extracthosts extractusnjrnl eyeballer eyepwn eyewitness facebash facebookosint facebot facebrok facebrute factordb-pycli fakeap fakedns fakemail fakenetbios fakenet-ng fang faradaysec fastnetmon favfreak fav-up fbht fbi fbid fcrackzip fdsploit featherduster fernflower fernmelder fern-wifi-cracker feroxbuster ffm ffuf ffuf-scripts fgscanner fhttp fi6s fierce fiked filebuster filefuzz filegps fileintel filibuster fimap finalrecon find3 find-dns findmyhash findmyiphone findomain findsploit fingerprinter firecat firefox-decrypt firefox-security-toolkit firewalk firmwalker firmware-mod-kit firstexecution firstorder fl0p flare flare-floss flashlight flashscanner flashsploit flask-session-cookie-manager2 flask-session-cookie-manager3 flasm flawfinder flowinspect flunym0us fluxion flyr fockcache forager foremost foresight forkingportscanner formatstringexploiter fortiscan fpdns fping fport fprotlogparser fraud-bridge fred freeipmi freeradius freewifi frida frida-extract frida-ios-dump fridump frisbeelite fscan f-scrack fs-exploit fsnoop fs-nyarl fssb fstealer ftester ftp-fuzz ftpmap ftp-scanner ftpscout ftp-spider fuddly fusil fuxploider fuzzap fuzzball2 fuzzbunch fuzzdb fuzzdiff fuzzowski fuzztalk g72x++ gadgetinspector gadgettojscript galleta gasmask gatecrasher gau gcat gcpbucketbrute gcrypt gdb gdb-common gdbgui gef gene genisys genlist geoedge geoip geoipgen gerix-wifi-cracker gethsploit getsids getsploit gf gggooglescan gg-images gh-dork ghettotooth ghidra ghostdelivery ghost-phisher ghost-py gibberish-detector girsh giskismet gitdorker git-dump gitdump git-dumper gitem gitgraber githack git-hound githubcloner github-dorks gitleaks gitmails gitminer gitrecon gitrob gittools git-wild-hunt gloom glue gmsadumper gnuradio gnutls2 gobd gobuster gocabrito goddi goldeneye golismero gomapenum goodork goofile google-explorer googlesub goog-mail goohak goop gooscan gopherus gophish gosint gospider gostringsr2 gowitness gplist gpocrack gpredict gps-sdr-sim gqrx grabbb grabber grabing grabitall graffiti gr-air-modes grammarinator graphqlmap graphql-path-enum graudit grepforrfi gr-gsm grokevt gr-paint grr grype gsd gsocket gspoof gtalk-decode gtfo gtfoblookup gtp-scan guymager gwcheck gwtenum h2buster h2csmuggler h2spec h2t h8mail habu hackersh hackredis hackrf haiti haka hakku hakrawler hakrevdns halberd halcyon halcyon-ide hamster handle harness harpoon hasere hash-buster hashcat hashcatch hashcat-utils hashcheck hashdb hashdeep hasher hash-extender hashfind hashid hash-identifier hashpump hashtag hatcloud hate-crack haystack hbad hcraft hcxdumptool hcxkeys hcxtools hdcp-genkey hdmi-sniff heaptrace heartbleed-honeypot heartleech hellraiser hemingway hercules-payload hetty hex2bin hexinject hexorbase hexyl hharp hidattack hiddeneye hiddeneye-legacy hikpwn hlextend hodor holehe hollows-hunter homepwn honeycreds honeyd honeypy honggfuzz honssh hookanalyser hookshot hoover hoper hopper hoppy hostapd-wpe hostbox-ssh host-extract hosthunter hotpatch hotspotter howmanypeoplearearound hpfeeds hping hqlmap hsecscan htcap htexploit htpwdscan htrosbif htshells http2smugl httpbog http-enum httpforge http-fuzz httpgrep httping http-put httppwnly httprecon httprint httprint-win32 httprobe httpry httpscreenshot httpsniff httpsscanner http-traceroute httptunnel httpx httrack hubbit-sniffer hulk hungry-interceptor hurl hwk hxd hyde hydra hyenae hyperfox hyperion-crypter i2pd iaito iaxflood iaxscan ibrute icloudbrutter icmpquery icmpsh icmptx idb id-entify identywaf idswakeup ifchk ifuzz iheartxor iisbruteforcer iis-shortname-scanner ikecrack ikeforce ikeprobe ikeprober ike-scan ilo4-toolbox ilty imagegrep imagejs imagemounter imhex impacket impulse inception indx2csv indxcarver indxparse inetsim infection-monkey infip infoga inguma injectus innounp inquisitor insanity instagramosint instashell intelmq intelplot intensio-obfuscator interactsh-client intercepter-ng interlace interrogate intersect intrace inundator inurlbr inviteflood invoke-cradlecrafter invoke-dosfuscation invoke-obfuscation inzider iodine iosforensic ip2clue ipaudit ipba2 ipcountry ipdecap iphoneanalyzer ip-https-tools ipmipwn ipmitool ipobfuscator ipscan ipsourcebypass iptodomain ip-tracer iptv iputils ipv4bypass ipv666 ipv6toolkit ircsnapshot irpas isf isip isme isr-form issniff ivre ivre-docs ivre-web ja3 jaadas jackdaw jad jadx jaeles jaidam jast javasnoop jboss-autopwn jbrofuzz jbrute jcrack jd-cli jdeserialize jd-gui jeangrey jeb-android jeb-arm jeb-intel jeb-mips jeb-webasm jeopardize jexboss jhead jira-scan jndi-injection-exploit jnetmap john johnny jok3r jomplug jondo jooforce joomlascan joomlavs joomscan jpegdump jpexs-decompiler jsearch jsfuck jshell jsonbee jsparser jsql-injection jstillery juicy-potato junkie justdecompile juumla jwscan jwtcat jwt-cracker jwt-hack jwt-tool jynx2 k55 kacak kadimus kalibrate-rtl kamerka katana katsnoop kautilya kcptun keimpx kekeo kerbcrack kerberoast kerbrute kernelpop keye khc kickthemout killcast killerbee kimi kippo kismet kismet2earth kismet-earth kismon kiterunner kitty-framework klar klee klogger knock knxmap koadic kolkata konan kraken krbrelayx kube-hunter kubesploit kubestriker kubolt kwetza l0l laf lanmap2 lans latd laudanum lazagne lazydroid lbd lbmap ldap-brute ldapdomaindump ldapenum ldapscripts ldeep ld-shatner ldsview leaklooker leena legion leo leroy-jenkins lethalhta letmefuckit-scanner leviathan levye lfi-autopwn lfi-exploiter lfifreak lfi-fuzzploit lfi-image-helper lfimap lfi-scanner lfi-sploiter lfisuite lfle lft lhf libbde libc-database libdisasm libfvde libosmocore libparistraceroute libpst libtins lief liffy lightbulb ligolo-ng limeaide limelighter linenum linikatz linkedin2username linkfinder linset linux-exploit-suggester linux-exploit-suggester.sh linux-inject linux-smart-enumeration lisa.py list-urls littleblackbox littlebrother lldb loadlibrary local-php-security-checker locasploit lodowep log4j-bypass log4j-scan log-file-parser logkeys logmepwn loic loki-scanner lolbas loot lorcon lorg lorsrf lotophagi lsrtunnel lte-cell-scanner ltrace luksipc lulzbuster lunar luyten lynis lyricpass m3-gen macchanger machinae maclookup mac-robber magescan magicrescue magictree maigret mail-crawl make-pdf maketh malcom malheur malice maligno mallory malmon malscan maltego maltrail maltrieve malwareanalyser malware-check-tool malwaredetect malwasm malybuzz mana mando.me manspider manticore manul mara-framework marc4dasm marshalsec maryam maskprocessor massbleed masscan masscan-automation massdns massexpconsole mat mat2 matahari matroschka mausezahn mbenum mboxgrep mdbtools mdcrack mdk3 mdk4 mdns-recon meanalyzer medusa meg melkor memdump memfetch memimager mentalist merlin-server metabigor metacoretex metafinder metaforge metagoofil metame metasploit metasploit-autopwn meterssh metoscan mfcuk mfoc mfsniffer mft2csv mftcarver mftrcrd mftref2name mibble microsploit middler mikrotik-npk mildew mimikatz mimipenguin mingsweeper minimodem minimysqlator miranda-upnp missidentify missionplanner mitm mitm6 mitmap mitmap-old mitmer mitmf mitmproxy mitm-relay mkbrutus mkyara mobiusft mobsf modlishka modscan moloch mongoaudit monocle monsoon mooscan morpheus morxbook morxbrute morxbtcrack morxcoinpwn morxcrack morxkeyfmt morxtraversal morxtunel mosca mosquito mots motsa-dns-spoofing mousejack mp3nema mptcp mptcp-abuse mqtt-pwn mrsip mrtparse msfdb msfenum msf-mpc msmailprobe mssqlscan ms-sys msvpwn mtr mtscan mubeng multiinjector multimac multimon-ng multiscanner multitun munin-hashchecker muraena mutator mwebfp mxtract mybff myjwt mylg mysql2sqlite n1qlmap naabu nacker naft narthex nasnum nbname nbnspoof nbtenum nbtool nbtscan ncpfs ncrack necromant needle neglected neighbor-cache-fingerprinter nemesis neo-regeorg netactview netattack netbios-share-scanner netbus netcommander netcon net-creds netdiscover netkit-bsd-finger netkit-rusers netkit-rwho netmap netmask netreconn netripper netscan netscan2 netsed netsniff-ng netstumbler nettacker network-app-stress-tester networkmap networkminer netz netzob nexfil nextnet nfcutils nfdump nfex nfspy nfsshell ngrep ngrok nield nikto nili nimbostratus nipe nipper nirsoft nishang njsscan nkiller2 nmap nmap-parse-output nmbscan nohidy nomorexor noriben nosqlattack nosqli nosqli-user-pass-enum nosqlmap notspikefile novahot nray nsdtool nsearch nsec3map nsec3walker nsntrace nsoq ntds-decode ntdsxtract ntfs-file-extractor ntfs-log-tracker ntlm-challenger ntlmrecon ntlm-scanner ntlm-theft ntpdos ntp-fingerprint ntp-ip-enum nuclei nullinux nullscan nxcrypt nzyme o365enum o365spray oat obevilion obexstress obfs4proxy objdump2shellcode objection oclhashcat ocs office-dde-payloads ofp-sniffer ohrwurm okadminfinder oledump ollydbg omen omnibus omnihash one-lin3r onesixtyone onetwopunch onioff oniongrok onionscan onionsearch onionshare opendoor open-iscsi openpuff openscap openstego opensvp openvas-scanner operative ophcrack orakelcrackert origami orjail o-saft oscanner osfooler-ng osi.ig osinterator osint-spy osrframework osslsigncode ostinato osueta otori outguess outlook-webapp-brute owabf owasp-bywaf owasp-zsc owtf p0f pack packer packerid packeth packet-o-matic packetq packetsender packit pacu pacumen padbuster pafish pagodo paketto panhunt panoptic pappy-proxy parameth parampampam paranoic paros parse-evtx parsero pasco passcracking passe-partout passhunt passivedns pass-station pastejacker pastemonitor pasv-agrsv patator patchkit pathzuzu payloadmask payloadsallthethings pblind pbscan pcapfex pcapfix pcapsipdump pcapteller pcapxray pcileech pcode2code pcredz pdblaster pdfbook-analyzer pdfcrack pdfgrab pdfid pdf-parser pdfresurrect pdfwalker pdgmail peach peach-fuzz peass pe-bear peda peepdf peepingtom peframe pemcrack pemcracker penbox pencode pentbox pentestly pentmenu pepe pepper periscope perl-image-exiftool pe-sieve petools pev pextractor pftriage pgdbf phantap phantom-evasion phemail phishery phishingkithunter phoneinfoga phonesploit phonia phoss photon php-findsock-shell phpggc php-malware-finder php-mt-seed php-rfi-payload-decoder phpsploit phpstan phpstress php-vulnerability-hunter phrasendrescher pidense pin pingcastle pintool pintool2 pip3line pipal pipeline pirana pivotsuite pixd pixiewps pixload pkcrack pkinittools pkt2flow plasma-disasm plcscan plecost plown plumber.py plutil pmacct pmap pmapper pmcma pmdump pngcheck pnscan pocsuite poison poly polyswarm pompem poracle portia portmanteau portspoof postenum posttester powercloud powerfuzzer powerlessshell powermft powerops powershdll powersploit powerstager pown ppee ppfuzz ppmap ppscan pr0cks prads praeda preeny pret princeprocessor procdump proctal procyon profuzz prometheus-firewall promiscdetect propecia protosint protos-sip prowler proxenet proxify proxmark proxmark3 proxybroker proxychains-ng proxycheck proxyp proxyscan proxytunnel ps1encode pscan pshitt pspy pstoreview ptf pth-toolkit ptunnel pulledpork pulsar punk punter pupy pureblood pwcrack pwd-hash pwdlogy pwdlyser pwdump pwnat pwncat pwncat-caleb pwndbg pwndora pwndrop pwned pwnedornot pwnedpasswords pwned-search pwnloris pwntools pyaxmlparser pybozocrack pydictor pyersinia pyew pyexfil pyfiscan pyfuscation pyinstaller pyjfuzz pykek pymeta pyminifakedns pyrasite pyrdp pyrit pyssltest pytacle pytbull pythem python2-api-dnsdumpster python2-capstone python2-cymruwhois python2-darts.util.lru python2-exrex python2-frida python2-frida-tools python2-google-streetview python2-hpfeeds python2-ivre python2-jsbeautifier python2-ldapdomaindump python2-minidump python2-minikerberos python2-oletools python2-pcodedmp python2-peepdf python2-ropgadget python2-shodan python2-yara python-api-dnsdumpster python-arsenic python-capstone python-cymruwhois python-frida python-frida-tools python-google-streetview python-ivre python-jsbeautifier python-keylogger python-minidump python-mmbot python-oletools python-pcodedmp python-search-engine-parser python-shodan python-ssh-mitm python-trackerjacker python-uncompyle6 python-utidylib python-witnessme python-yara-rednaga qark qrgen qrljacker qsreplace quark-engine quickrecon quicksand-lite quickscope r2ghidra rabid raccoon radamsa radare2 radare2-keystone radare2-unicorn radiography rainbowcrack ranger-scanner rapidscan rarcrack rasenum rathole ratproxy rats raven rawr rawsec-cli rbasefind rbkb rbndr rcracki-mt rcrdcarver rdesktop-brute rdpassspray rdp-cipher-checker rdp-sec-check rdwarecon reaver rebind recaf recentfilecache-parser recomposer recon-ng reconnoitre reconscan recoverjpeg recsech recstudio recuperabit redasm redfang red-hawk redirectpoison redpoint redress redsocks reelphish regeorg regipy reglookup regreport regrippy regview rekall relay-scanner remot3d replayproxy resourcehacker responder restler-fuzzer retdec retire reverseip revipd revsh rex rext rfcat rfdump rfidiot rfidtool rhodiola richsploit ridenum ridrelay rifiuti2 rinetd ripdc rita riwifshell rkhunter rlogin-scanner rmiscout roguehostapd rogue-mysql-server rombuster rootbrute ropeadope ropeme ropgadget ropper roputils routerhunter routersploit rp rpak rpcsniffer rpctools rpdscan rpivot rr rrs rsactftool rsakeyfind rsatool rshack rsmangler rspet rtfm rtlamr rtlizer rtlsdr-scanner rtpbreak rtp-flood rubilyn ruler rulesfinder rupture rustbuster rustcat rustpad rustscan rvi-capture rww-attack rz-cutter rz-ghidra s3-fuzzer s3scanner safecopy sagan sakis3g saleae-logic sambascan samdump2 samesame samplicator samydeluxe sandcastle sandmap sandsifter sandy saruman sasm sawef sb0x sbd scalpel scamper scanless scanmem scannerl scanqli scansploit scanssh scap-security-guide scap-workbench scapy scavenger schnappi-dhcp sc-make scout2 scoutsuite scrape-dns scrapy scratchabit scrounge-ntfs scrying sctpscan scylla sdnpwn sdn-toolkit sea search1337 seat second-order secretfinder secscan secure2csv secure-delete seeker sees see-surf sensepost-xrdp sergio-proxy serialbrute serializationdumper server-status-pwn sessionlist set seth setowner sfuzz sgn sh00t sha1collisiondetection shad0w shadowexplorer shard shareenum sharesniffer shed shellcheck shellcode-compiler shellcodecs shellcode-factory shellen shellerator shellinabox shelling shellme shellnoob shellpop shellsploit-framework shellter sherlock sherlocked shhgit shitflood shocker shodanhat shootback shortfuzzy shreder shuffledns sickle sidguesser siege sigma sign sigploit sigspotter sigthief silenteye silenttrinity silk simple-ducky simpleemailspoofer simple-lan-scan simplify simplyemail simtrace2 sinfp siparmyknife sipbrute sipcrack sipffer sipi sipp sippts sipsak sipscan sipshock sipvicious sireprat sitadel sitediff sjet skipfish skiptracer skul skydive skyjack skype-dump skypefreak slackpirate sleuthkit sleuthql slither sloth-fuzzer slowhttptest slowloris slowloris-py slurp-scanner smali smali-cfgs smalisca smap smartphone-pentest-framework smbbf smbcrunch smbexec smbmap smbrelay smbspider smbsr smikims-arpspoof smod smplshllctrlr smtp-fuzz smtpmap smtpscan smtp-test smtptester smtptx smtp-user-enum smtp-vrfy smuggler smuggler-py sn00p sn1per snallygaster snapception snare snarf-mitm sniffer sniffglue sniffjoke sniffles sniff-probe-req snitch snmpattack snmp-brute snmpcheck snmpenum snmp-fuzzer snmpscan snoopbrute snoopy-ng snort snow snowman snscan snuck snyk soapui socat social-analyzer socialfish social-mapper socialpwned socialscan social-vuln-scanner socketfuzz sockstat soot sooty spade spaf sparta spartan sparty spectools speedpwn spf spfmap spiderfoot spiderpig-pdffuzzer spiga spike-fuzzer spike-proxy spiped spipscan splint sploitctl sploitego spoofcheck spooftooph spookflare spotbugs spray365 spraycharles sprayingtoolkit spraykatz sps spyse sqid sqlbrute sqldict sqlivulscan sqlmap sqlninja sqlpat sqlping sqlpowerinjector sqlsus ssdeep ssdp-scanner sshatter ssh-audit sshfuzz ssh-honeypot ssh-mitm sshprank ssh-privkey-crack sshscan sshtrix sshtunnel ssh-user-enum sshuttle sslcat sslcaudit ssldump sslh ssl-hostname-resolver ssllabs-scan sslmap sslnuke ssl-phuck3r sslscan sslscan2 sslsniff sslstrip sslyze ssma ssrfmap ssrf-proxy ssrf-sheriff stackflow stacoan stacs staekka stardox starttls-mitm statsprocessor stegcracker stegdetect steghide stegolego stegosip stegoveritas stegsolve stenographer stepic stews sticky-keys-hunter stig-viewer stompy stoq storm-ring strace streamfinder striker stringsifter striptls strutscan stunnel sub7 subbrute subdomainer subfinder subjack subjs sublert sublist3r subover subscraper subterfuge sucrack suid3num sulley superscan suricata suricata-verify svn-extractor swaks swamp swap-digger swarm swfintruder swftools syborg sylkie syms2elf synflood synner synscan syringe sysdig sysinternals-suite t50 tabi tachyon-scanner tactical-exploitation taipan takeover talon taof tbear tcgetkey tchunt-ng tcpcontrol-fuzzer tcpcopy tcpdstat tcpdump tcpextract tcpflow tcpick tcpjunk tcpreplay tcptrace tcptraceroute tcpwatch tcpxtract teamsuserenum teardown tekdefense-automater tell-me-your-secrets tempomail termineter testdisk testssl.sh tfsec tftp-bruteforce tftp-fuzz tftp-proxy tgcd thc-ipv6 thc-keyfinder thc-pptp-bruter thcrut thc-smartbrute thc-ssl-dos thedorkbox thefatrat thefuzz theharvester themole threatspec thumbcacheviewer tidos-framework tiger tilt timegen tinc tinfoleak tinfoleak2 tinyproxy tls-attacker tlsenum tls-fingerprinting tlsfuzzer tls-map tlspretense tls-prober tlssled tnscmd token-hunter token-reverser tomcatwardeployer topera tor tor-autocircuit tor-browser-en torcrawl torctl torpy tor-router torshammer torsocks tpcat tplmap traceroute trape traxss treasure trevorspray trid trinity triton trivy trixd00r truegaze truehunter trufflehog trusttrees tsh tsh-sctp ttpassgen tunna tweets-analyzer tweetshell twint twofi typo3scan tyton u3-pwn uacme uatester uberfile ubertooth ubiquiti-probing ubitack udis86 udork udp2raw-tunnel udpastcp udp-hunter udptunnel udsim uefi-firmware-parser ufonet ufo-wardriving uhoh365 ultimate-facebook-scraper umap umit uncaptcha2 unfurl unhide unibrute unicorn-powershell unicornscan unifuzzer uniofuzz uniscan unix-privesc-check unsecure unstrip untwister upnp-pentest-toolkit upnpscan uppwn uptux upx urh urlcrazy urldigger urlextractor urlview usb-canary usbrip username-anarchy usernamer userrecon userrecon-py usnjrnl2csv usnparser uw-loveimap uw-offish uw-udpscan uw-zone v3n0m vais valabind valgrind valhalla vane vanguard vault-scanner vba2graph vbrute vbscan vbsmin vcsmap vega veil veles venom veracrypt verinice vfeed vhostscan videosnarf vinetto viper vipermonkey viproy-voipkit virustotal visql visualize-logs vivisect vlan-hopping vlany vmap vnak vnc-bypauth vncrack voiper voiphopper voipong volafox volatility3 volatility-extra voltron vpnpivot vsaudit vscan vstt vsvbp vulmap vulnerabilities-spider vulnx vuls vulscan w13scan w3af wafninja wafp wafpass wafw00f waidps waldo wapiti wascan wavemon waybackpack waybackurls wcc wce wcvs web2ldap webacoo webanalyze webborer webenum webexploitationtool webfixy webhandler webhunter webkiller webpwn3r webrute webscarab websearch webshag webshells webslayer websockify web-soul webspa websploit webtech webxploiter weebdns weeman weevely weirdaal wepbuster wesng wfuzz whapa whatbreach whatportis whatsmyname whatwaf whatweb whichcdn whispers whitewidow wi-feye wifi-autopwner wifibroot wifichannelmonitor wificurse wifi-honey wifijammer wifi-monitor wifiphisher wifi-pumpkin wifiscanmap wifitap wifite wig wikigen wildpwn windapsearch windivert windows-binaries windows-exploit-suggester windows-prefetch-parser windows-privesc-check windowsspyblocker winexe winfo winhex winpwn winregfs winrelay wireless-ids wireshark-cli wireshark-qt wirouter-keyrec witchxtool wlan2eth wmat wmd wmi-forensics wnmap wol-e wolpertinger wondershaper wordbrutepress wordlistctl wordlister wordpot wordpresscan wordpress-exploit-framework wpa2-halfhandshake-crack wpa-bruteforcer wpbf wpbrute-rpc wpbullet wpforce wpintel wpscan wpseku wpsik wpsweep wreckuests ws-attacker wscript wsfuzzer wssip wsuspect-proxy wups wuzz wxhexeditor wyd x64dbg x8 xcat xcavator xcname xerosploit xfltreat xmlrpc-bruteforcer xorbruteforcer xorsearch xortool xpire-crossdomain-scanner xplico xpl-search xprobe2 xray xrop x-rsa x-scan xspear xspy xsrfprobe xsscon xsscrapy xsser xss-freak xssless xsspy xsss xssscan xsssniper xsstracer xsstrike xssya xwaf xxeinjector xxeserv xxexploiter xxxpwn xxxpwn-smart yaaf yaf yara yasat yasca yasuo yate-bts yawast ycrawler yersinia yeti yinjector ysoserial zackattack zaproxy zarp zdns zeek zeek-aux zelos zeratool zerowine zeus zeus-scanner zgrab zgrab2 zipdump zipexec zirikatu zizzania zmap zssh zulu zulucrypt zykeys zzuf pfff
```
**Nota**:si algun paquete te da un error solo quitalo.

***Comandos opcionales:***
  - ```
    pacman -S blackarch-anti-forensic blackarch-automation blackarch-automobile blackarch-backdoor blackarch-binary blackarch-bluetooth blackarch-code-audit blackarch-config blackarch-cracker blackarch-crypto blackarch-database blackarch-debugger blackarch-decompiler blackarch-defensive blackarch-disassembler blackarch-dos blackarch-drone blackarch-exploitation blackarch-fingerprint blackarch-firmware blackarch-forensic blackarch-fuzzer blackarch-gpu blackarch-hardware blackarch-honeypot blackarch-ids blackarch-keylogger blackarch-malware blackarch-misc blackarch-mobile blackarch-networking blackarch-nfc blackarch-packer blackarch-proxy blackarch-radio blackarch-recon blackarch-reversing blackarch-scanner blackarch-sniffer blackarch-social blackarch-spoof blackarch-stego blackarch-tunnel blackarch-unpacker blackarch-voip blackarch-webapp blackarch-wireless
    ```
  - ```
    pacman -S blackarch
    ```
***Instalamos paru***
```
pacman -S git
```
```
mkdir -p ~/Desktop/user/repos
```
```
cd !$
```
```
git clone https://aur.archlinux.org/paru-bin.git
```
```
cd paru-bin
```
```
makepkg -si
```

***Instalacion de programas:***
```
sudo pacman -S kitty nautilus ranger libreoffice nvim gedit picom rofi
```
```
paru -S brave-bin
```
***Configurando Fluxbox***
```
cd ~/.fluxbox
```
```
rm menu
```
```
rm keys
```
```
rm startup
```
```
wget https://raw.githubusercontent.com/253AA/blackarch-install-dotfiles/main/menu
```
```
wget https://raw.githubusercontent.com/253AA/blackarch-install-dotfiles/main/keys
```
```
wget https://raw.githubusercontent.com/253AA/blackarch-install-dotfiles/main/startup
```
***Configurando la nueva Kitty***
1. Abrimos nuestra terminal kitty con Win+Enter
```
sudo pacman -S zsh
```
```
sudo su
```
```
usermod --shell /usr/bin/zsh/ user
```
Cierra y vuelve a abrir la consola
```
sudo su
```
```
localectl set-x11-keymap latam
```
```
reboot
```
Volvemos a abrir la terminal
```
rm -rf ~/.zshrc
```
```
wget https://raw.githubusercontent.com/253AA/blackarch-install-dotfiles/main/zshrc
```
```
mv ~/zshrc ~/.zshrc
```
```
paru -S zsh-syntax-kighlighting zsh-autosuggestions
```
```
sudo pacman -S locate
```
```
updatedb
```
Cierra y vuelve a abrir la terminal
```
cd /usr/share
```
```
sudo mkdir zsh-sudo
```
```
sudo chown user:user zsh-sudo/
```
```
cd !$
```
```
wget https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/plugins/sudo/sudo.plugin.zsh
```
Cierra y vuelve a abrir la terminal
```
sudo pacman -S lsd bat
```
```
paru -S scrub
```
Dirigete a [Nerd Fonts](https://www.nerdfonts.com/font-downloads), busca **Hack Nerd Font** y descargala.
```
cd /usr/share/fonts
```
```
sudo mv /home/user/Downloads/Hack.zip .
```
```
sudo unzip Hack.zip
```
```
rm Hack.zip
```
```
cd ~/.config/kitty/
```
```
rm kitty.conf
```
```
wget https://raw.githubusercontent.com/rxyhn/bspdots/main/config/kitty/color.ini
```
```
wget https://raw.githubusercontent.com/253AA/blackarch-install-dotfiles/main/kitty.conf
```
Cierra y vuelve a abrir la terminal
```
cd
```
```
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ~/powerlevel10k
```
```
echo 'source ~/powerlevel10k/powerlevel10k.zsh-theme' >>~/.zshrc
```
```
zsh
```
Cierra y vuelve a abrir la terminal
```
rm ~/.p10k.zsh
```
```
wget https://raw.githubusercontent.com/253AA/blackarch-install-dotfiles/main/p10k.zsh
```
```
mv p10k.zsh ~/.p10k.zsh
```
```
sudo su
```
```
ln -s -f /home/user/.zshrc /root/.zshrc
```
```
usermod --shell /usr/bin/zsh root
```
```
cd
```
```
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ~/powerlevel10k
```
```
echo 'source ~/powerlevel10k/powerlevel10k.zsh-theme' >>~/.zshrc
```
```
p10k configure
```
Cierra y vuelve a abrir la terminal
```
sudo su
```
```
cd
```
```
rm ~/.p10k.zsh
```
```
wget https://raw.githubusercontent.com/253AA/blackarch-install-dotfiles/main/p10k.zsh-root
```
```
mv p10k.zsh-root ~/.p10k.zsh
```
```
reboot
```
Inicia sesion y abre una terminal
```
git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf
```
```
~/.fzf/install
```
```
sudo su
```
```
git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf
```
```
~/.fzf/install
```
```
pacman -S neovim
```
```
exit
```
```
git clone https://github.com/NvChad/NvChad ~/.config/nvim --depth 1 && nvim
```
```
sudo su
```
```
git clone https://github.com/NvChad/NvChad ~/.config/nvim --depth 1 && nvim
```
***Instalando y configurando la polybar***
```
sudo pacman -S polybar
```
```
git clone https://github.com/VaughnValle/blue-sky.git
```
```
mkdir ~/.config/polybar
```
```
cd ~/blue-sky/polybar/
```
```
cp * -r ~/.config/polybar
```
```
cd fonts
```
```
sudo cp * /usr/share/fonts/truetype/
```
```
fc-cache -v
```
```
reboot
```
Iniciamos sesion y abrimos la terminal
```
mkdir ~/.config/bin
```
```
cd !$
```
```
wget https://raw.githubusercontent.com/253AA/blackarch-install-dotfiles/main/hackthebox_status.sh
```
```
wget https://raw.githubusercontent.com/253AA/blackarch-install-dotfiles/main/ethernet_status.sh
```
```
chmod +x ethernet_status.sh
```
```
chmod +x hackthebox_status.sh
```
```
cd ~/.config/polybar/scripts/themes/
```
```
rm powermenu_alt.rasi
```
```
wget https://raw.githubusercontent.com/253AA/blackarch-install-dotfiles/main/powermenu_alt.rasi
```
```
rm ~/.config/polybar/current.ini
```
```
rm ~/.config/polybar/workspace.ini
```
```
cd ~/.config/polybar/
```
```
wget https://raw.githubusercontent.com/253AA/blackarch-install-dotfiles/main/workspace.ini
```
```
wget https://raw.githubusercontent.com/253AA/blackarch-install-dotfiles/main/current.ini
```
```
mkdir ~/.config/picom
```
```
cd ~/.config/picom 
```
```
wget https://raw.githubusercontent.com/253AA/blackarch-install-dotfiles/main/picom.conf
```
Cerramos la sesion y la volvemos a iniciar
```






