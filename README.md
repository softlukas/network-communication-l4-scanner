   - [Testovanie na localhoste](#porovnanie-s-nmap)

## Obsah
1. [Úvod]()
2. [Teoretické východiská](#teoretické-východiská)
   - [TCP skenovanie](#tcp-skenovanie)
   - [UDP skenovanie](#udp-skenovanie)
   - [Packet]()
   - [Raw socket]()
3. [Zdrojové súbory]()
4. [Testovanie](#testovanie)
   - [Postup testovania](#testovacia-metodológia)
   - [Testovanie verejných IP adries](#testovacie-prípady)
   - [Testovanie v rámci lokálnej siete](#testovacie-prostredie)
   - [Testovanie na localhoste](#porovnanie-s-nmap)
6. [Bibliografia](#bibliografia)

## Úvod
Tento dokument popisuje vývoj a funkcionalitu sieťového scanera pracujúceho na 4. vrstve sieťového modelu TCP/IP. Skener využíva pokročilé techniky skenovania portov, ako je SYN skenovanie pre TCP a ICMP správy pre UDP, na detekciu stavu portov na zadaných IP adresách. Cieľom aplikácie je poskytovať rýchly a presný spôsob analýzy dostupnosti portov na cieľových zariadeniach, čo môže byť užitočné pri administrácii siete alebo pri diagnostike bezpečnostných problémov.


## Teoretické východiská

### TCP skenovanie
Skener používa SYN pakety na zisťovanie stavu TCP portov. Pri tomto type skenovania sa nevykonáva kompletný 3-way handshake. Odpoveď RST indikuje uzavretý port, zatiaľ čo žiadna odpoveď naznačuje, že port je filtrovaný.


### UDP skenovanie
Pri UDP skenovaní sa skener spolieha na ICMP správy (typ 3, kód 3), ktoré určujú stav uzavretého portu. Ak nebola prijatá odpoveď na UDP port, považuje sa za otvorený.

### Packet
V oblasti počítačových sietí je packet (paket) základnou jednotkou prenosu dát medzi zariadeniami v sieti. Packet obsahuje nielen dáta, ktoré sa prenášajú, ale aj hlavičku, ktorá obsahuje informácie o ceste, ktorou má paket prejsť, ako aj kontrolné údaje pre overenie správnosti prenosu. V protokole TCP/IP sa paket delí na dve hlavné časti: hlavičku a dáta.

### Raw socket
Raw socket je špeciálny typ socketu, ktorý umožňuje priamu manipuláciu s paketmi na úrovni sieťovej vrstvy. Na rozdiel od štandardných socketov, ktoré pracujú s vyššími vrstvami protokolového zásobníka (napr. TCP a UDP), raw sockety poskytujú možnosť odosielať a prijímať pakety bez zásahu operačného systému do ich obsahu.

Použitie raw socketov je nevyhnutné pri implementácii sieťových nástrojov, ako je skener portov, pretože umožňuje odosielanie vlastných paketov (napríklad SYN paketov pre TCP skenovanie) a ich následnú analýzu. Na prácu s raw socketmi je potrebné mať administrátorské oprávnenia, pretože ich nesprávne použitie môže viesť k bezpečnostným rizikám.

## Zdrojové súbory
### Program.cs

Tento súbor obsahuje hlavný vstupný bod programu. Jeho hlavnou úlohou je spracovanie vstupných argumentov a inicializácia procesu skenovania.

#### Hlavné funkcionality:
- **Spracovanie argumentov príkazového riadku**  
  - Program využíva knižnicu `CommandLine` na parsovanie argumentov.
  - Ak nie sú zadané povinné argumenty (`interface`, `target`, `tcp/udp ports`), zobrazí zoznam aktívnych sieťových rozhraní a ukončí sa.
  
- **Inicializácia parametrov skenovania**  
  - Vytvára objekt `ScanParams`, ktorý reprezentuje zadané vstupné parametre.

- **Volanie funkcií na skenovanie TCP a UDP portov**  
  - `ScanTcpPorts()` – vykoná skenovanie TCP portov.
  - `ScanUdpPorts()` – vykoná skenovanie UDP portov.

- **Pomocná funkcia `FillPortsList()`**  
  - Spracováva zadané porty a prevádza ich na zoznam jednotlivých hodnôt.
  - Podporuje zápis vo forme jednotlivých portov aj rozsahov (napr. `80,443` alebo `20-25`).

Tento súbor je základným bodom spustenia aplikácie, pričom zaisťuje správne spracovanie vstupných údajov a následné vykonanie skenovania.

### NetworkManager.cs

Tento súbor obsahuje pomocné sieťové funkcie potrebné na správne fungovanie skenera. Zahŕňa metódy na identifikáciu IP verzie, získanie IP adresy sieťového rozhrania, vytváranie paketov a riešenie doménových mien.

#### Hlavné funkcionality:

- **Detekcia verzie IP adresy (`IsIpv6Address`)**  
  - Overuje, či zadaná IP adresa patrí do IPv4 alebo IPv6.
  - V prípade neplatného formátu vypíše chybu a ukončí program.

- **Získanie IP adresy sieťového rozhrania (`GetSourceIpAddress`)**  
  - Prehľadáva sieťové rozhrania a vracia IPv4 alebo IPv6 adresu podľa požiadavky.
  - Ak sa IP adresa nenájde, vypíše chybové hlásenie a ukončí program.

- **Tvorba UDP paketu (`BuildUdpPacket`)**  
  - Vytvára hlavičku UDP paketu so zadanými portami.
  - Obsahuje 8-bajtovú hlavičku bez ďalšieho užívateľského payloadu.

- **Preklad doménového mena na IP adresy (`ResolveIpsFromDomain`)**  
  - Používa systémový DNS na získanie všetkých IP adries priradených k doménovému menu.
  - Ak preklad zlyhá, program vypíše chybu a ukončí sa.

- **Konverzia portu na bajtové pole (`SetPortBytes`)**  
  - Konvertuje port (ushort) na dvojbajtové pole vo veľkom endian formáte.

- **Výpočet kontrolného súčtu (`CalculateChecksum`)**  
  - Implementuje jednoduchý algoritmus na výpočet kontrolného súčtu podľa štandardného sieťového postupu.
  - Používa sa pre rôzne sieťové hlavičky na zabezpečenie integrity dát.

Tento súbor poskytuje kľúčové sieťové operácie, ktoré umožňujú správne zostavovanie paketov a komunikáciu cez sieťové rozhrania.

### Packet.cs

Tento súbor definuje triedu `Packet`, ktorá reprezentuje sieťový paket a umožňuje jeho zostavenie pre protokoly TCP a UDP.



#### Hlavné metódy:

- **Konstruktor `Packet(...)`**  
  - Inicializuje objekt `Packet` so zadanými parametrami.

- **`BuildPacket()`**  
  - Vytvára kompletný IP paket s TCP alebo UDP hlavičkou.
  - Vytvára IP hlavičku, nastavuje správne polia a počíta kontrolný súčet.
  - Pre TCP generuje pseudo-hlavičku na výpočet kontrolného súčtu.

- **`CreateUdpHeader(...)`**  
  - Generuje 8-bajtovú UDP hlavičku so zdrojovým a cieľovým portom.
  - Nastavuje dĺžku UDP segmentu a kontrolný súčet na nulu.

- **`CreatetcpUdpHeader(...)`**  
  - Generuje 20-bajtovú TCP hlavičku s nastaveným SYN bitom.
  - Nastavuje sekvenčné a potvrdzovacie čísla na 0.
  - Vytvára základné TCP nastavenia ako veľkosť okna a checksum placeholder.

Tento súbor je kľúčový pre zostavovanie paketov v rámci skenera, umožňuje správne formátovanie TCP a UDP paketov pred ich odoslaním.


### ScanParams.cs

Tento súbor vykonáva samotné skenovanie.

- **Konštruktor `ScanParams(...)`**  
  - Inicializuje vstupné argumenty skenovania. Zároveň pri uložení cieľovej IP adresy sa určí jej formát, a v prípade potreby sa určí ip adresa z doménového mena pomocou DNS.
  
- **`SendSynPacket(...)`**
  - Funckia vykonáva TCP scan. Vytvorí SYN packet, pomocou raw socketu ho priradí k rozhraniu na základe IP adresy, a paket odošle. Hneď potom začne bežať časový limit na odpoveď. Odpoveď zachytávam pomocou knižnice SharpPcap, kde filtrujem pakety ktoré sú TCP, a kde sa zhodujú IP adresy a porty. Na základe odpovede rozhodnem o stave portu, v prípade že odpoveď nedorazí funkciu volám rekurzívne znova, a až potom označujem port ako filtered.
  
- **SendUdpPacket(...)`**
    - Postup je pododný ako pri tcp skene, rozdiel je v zachytávaní odpovedí, kde filtrujem pakety ktoré sú icmp typ 3 kód 3.

  

## Testovanie

### Postup testovania
Projekt som testoval na referenčnom virtuálnom stroji, kde som si vytvoril testovací script, ktorý porovnáva výstupy môjho skenera s výstupmi zo skenera Nmap. V tomto bol Nmap referenčný výstup. Na každom cieli som testoval vybrané tcp a udp porty, pre verziu IPv4 aj IPv6.



### Testovanie verejných IP adries
Testoval som niektoré vybrané tcp a udp porty na IP adresách dostupných na nmap.org pre Ipv4 aj IPv6.

Testoval som aj na adresách ktoré sa preložia z doménového mena google.com, tu bola väčšina portov filtered (udp open), čo preukázalo že môj program funguje správne aj v takomto prípade a ako odpoveď nezachytí "cudzí paket".

#### Príklad testu na cieľovej adrese z nmap.org


```sh
./ipk-l4-scan -i enp0s3 -t 21,22,143,80 -u 67 -w 1500 45.33.32.156

45.33.32.156 21 tcp closed
45.33.32.156 22 tcp open
45.33.32.156 143 tcp closed
45.33.32.156 80 tcp open
45.33.32.156 67 udp open
```

#### Na testovanie IPv6 som musel použiť FIT vpn, a teda rozhranie tun0:
```sh
./ipk-l4-scan --interface tun0 --pt 21,22,143,80 --pu 67 2600:3c01::f03c:91ff:fe18:bb2f
2600:3c01::f03c:91ff:fe18:bb2f 21 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 22 tcp open
2600:3c01::f03c:91ff:fe18:bb2f 143 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 80 tcp filtered
2600:3c01::f03c:91ff:fe18:bb2f 67 udp open
```


### Testovanie v rámci lokálnej siete

V rámci lokálnej siete som si zapol druhý virtuálny stroj, nastavil som tam niektoré porty na open/closed, a potom ručne porovnal výstupy z Nmap s mojím programom pre danú adresu v lokálnej sieti.

### Testovanie na localhoste (lo)
Rovnaký postup ako pri lokálnej sieti, nastavil som si vybrané porty, následne spustil môj script a porovnal výsledky.

### Wireshark
Program wireshark som využíval počas vývoja, kde som kontroloval správnosť odoslaného packetu, a taktiež prichádzajúce odpovede. Na zakláde analýzy dát z wiresharku som potom upravoval tvorbu paketu alebo filtrovanie správneho paketu pri zachytávaní odpovede.


## Bibliografia
- RFC 793: Transmission Control Protocol, 1981.
- RFC 791: Internet Protocol, 1981.
- RFC 768: User Datagram Protocol, 1980.
- [Nmap](https://nmap.org/nmap_doc.html#port_unreach) The Art of Port Scanning.
- Microsoft Socket class documentation [https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.socket?view=net-9.0]()
