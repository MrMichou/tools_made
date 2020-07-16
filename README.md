<h1>Note</h1>
<h3>Bash/shell scripts</h3>
<ul>
<li>auto-tcpdump : <br>If you use it setup ifstat and a crontab X minutes whatever</li>
<li>geoloc : <br>Look how works the script to use it proprely</li>
<li>alert_cron : <br>Send an alert on telegram if there is go upper the value it's set</li>
<li>whitlist_ipset: Script for ethernium for the frist project to avoid useless drop from FR users</li>
</ul>
<h3>Python script</h3>
<h4>Python Whitlist</h4>
Tool made for ethernium.net to whitlist threw a database, can be improved
<h4>Python Sniffer</h4>
<h3>This is old code during my free time</h3>
Need to improve the script<br>
Ifstat recupere les valeurs RX et TX au moment meme de la prise <br>
A regarder pour un subprocess plus cool <br>
Prise de packet done, faut changer les appelles de certaine prise de packet dont les dates <br>
Faire une prise de packet de TCP et UDP (Pour UDP faire un appel de Hashlimit) <br>
Faire un script de moyenne Heure / Jour / Semaine  <br>
Machine learning process by data analyse <br>

A faire :
Faire un fichier pour prendre les packets moyen permettant de faire une moyenne  <br>
Systeme de "flag" ou array_pourcentage pour reduire les faux positif <br>
Comment je pourrais faire une diag entre les variables ? <br>
Si il y a peu d'ip il faut reduire les chances que cela est un DDoS <br>
Autre Element, je sais que les attaques arrivent super rapidement avec les connexions internet <br>
Se fier par rapport au traffic garder les IP qui sont connecter et bannir les autre temporairement <br>
Si le traffic passe de de 5 % a 200 % de la valeur  <br>
Est-ce qu'on utilise le systeme de flag ? <br>
Parti action : <br>
subprocess.call(["iptables", "-A", "INPUT", "-s", arg, "-j", "DROP"]) <br>
Store data find partern and Looking threw the ip's to see if the others is using it <br>
# Recherche / Source : <br>
https://coreygoldberg.blogspot.ca/2010/09/python-linux-parse-network-stats-from.html <br>
https://stackoverflow.com/questions/30686295/how-do-i-run-multiple-subprocesses-in-parallel-and-wait-for-them-to-finish-in-py?rq=1 <br>
https://www.binarytides.com/python-packet-sniffer-code-linux/ <br>
https://stackoverflow.com/questions/21095134/calculate-bandwidth-usage-per-ip-with-scapy-iftop-style <br>
Multiprocessing https://www.linuxjournal.com/content/multiprocessing-python <br>
Threading Loop https://stackoverflow.com/questions/18773474/simple-way-to-run-two-while-loops-at-the-same-time-using-threading <br>
Binary file https://www.devdungeon.com/content/working-binary-data-python <br>
