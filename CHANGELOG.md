## Problémy s IPv6

Nakoľko kolejnet nepodporuje IPv6, bolo toto treba obísť rôznymi spôsobmi, či už FIT VPN, alebo ak váš mobilný operátor IPv6 poskytuje, mohli ste si urobiť hotspot. Na FIT VPN a teda cez rozhranie `tun0` mi IPv6 scan fungoval, avšak u kamaráta práve cez mobilné dáta, kde on mal konektivitu dostupnú na `enp0s3`, už nie.

## Multithreading

Skúšal som aplikáciu robiť paralelne, čiže každé poslanie a následný scan konkrétneho portu. Tu však odpovede nie vždy boli zachytené, ak nebolo práve spustené dané vlákno.

## UDP port 53

Nmap tento port skenuje tak, že naň pošle DNS request, podľa Wiresharku. Čo som sa dočítal, tak DNS môže niekedy ignorovať prichádzajúce pakety, tým pádom môj UDP paket poslaný na port 53 nedostal ICMP odpoveď, takže sa označil ako otvorený (hoci podľa Nmap by mal byť zatvorený).

