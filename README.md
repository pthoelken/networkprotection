# Network Protection

Dieses Projekt pflegt eine externe IPv4-Blockliste, eine lokale Custom-Liste,
konfigurierbare Ländersperren und Spamhaus ASN-DROP in einem idempotenten
systemd-Dienst. Ein Timer startet den Dienst nach dem Boot und danach alle
24 Stunden.

## Firewall-Aufbau

Das Skript erstellt ausschließlich:

- das IP-Set `networkprotection_v4` für blocklist.de und lokale Einträge,
- das IP-Set `networkprotection_geo_v4` für die gesperrten Länder,
- die IP-Sets `networkprotection_asn_v4` und `networkprotection_asn_v6` für
  Spamhaus ASN-DROP,
- die eigene Chain `NETWORKPROTECTION` in `iptables` und `ip6tables`,
- je einen kommentierten Sprung von `INPUT` nach `NETWORKPROTECTION`.

Die Sprünge werden bei jedem Lauf an Position 1 gesetzt. Vorhandene Regeln
rutschen nur gemeinsam nach unten; Inhalt und relative Reihenfolge bleiben
unverändert. Das Skript leert keine fremde Chain, stoppt weder Fail2ban noch
CrowdSec und schreibt kein globales `iptables-save`-Abbild.

Innerhalb der IPv4-Chain gilt diese Reihenfolge:

1. externe und lokale IPv4-Blockliste über `ipset`;
2. Länderblockliste über ein zweites `ipset`;
3. Spamhaus ASN-DROP über das IPv4-ASN-Set.

Die IPv6-Chain prüft das IPv6-ASN-Set. Alle Regeln verwenden ausschließlich den
Standard-Matcher `-m set --match-set ... src`. `xt_geoip`, xtables-addons,
DKMS, Kernel-Header und eine MOK-Einschreibung sind nicht erforderlich. Secure
Boot bleibt davon unberührt.

## GeoIP-Verarbeitung

Der Dienst lädt monatlich die kostenlose DB-IP Country Lite CSV-Datei. Der
mitgelieferte Python-Konverter filtert die in `BLOCK_COUNTRIES` konfigurierten
Länder, verwirft IPv6-Zeilen und wandelt IPv4-Start-/Endbereiche mit der
Python-Standardbibliothek in zusammengefasste CIDR-Netze um.

Neue Sets werden vollständig im Hintergrund aufgebaut und anschließend per
`ipset swap` atomar aktiviert. Download-, Dekompressions-, CSV- oder
Importfehler lassen das zuvor aktive Set unverändert. Die Konvertierung schlägt
auch fehl, wenn für eines der konfigurierten Länderkürzel keine IPv4-Daten
gefunden wurden.

## Spamhaus ASN-DROP

Bei jedem Lauf lädt der Dienst die aktuelle JSON-Lines-Datei von:

```text
https://www.spamhaus.org/drop/asndrop.json
```

Die Metadaten und jede ASN werden validiert. Anschließend löst der
Python-Konverter jede ASN über den RIPEstat-Endpunkt `announced-prefixes` auf:

```text
https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS<ASN>
```

Alle Antworten müssen erfolgreich und vollständig sein. Die gelieferten
öffentlichen IPv4- und IPv6-Präfixe werden mit der Python-Standardbibliothek
validiert, dedupliziert und zusammengefasst. Erst danach befüllt das Skript
beide temporären Sets. Die finalen IPv4- und IPv6-Sets werden einzeln per
`ipset swap` aktiviert; schlägt der zweite Tausch wider Erwarten fehl, wird der
erste zurückgetauscht. Download-, API-, JSON-, Validierungs- oder Importfehler
lassen ein bereits vorhandenes Set-Paar unverändert.

Standardmäßig laufen vier RIPEstat-Abfragen parallel. Der Wert ist auf maximal
acht begrenzt. Da jede ASN bei jedem Dienstlauf erneut aufgelöst wird, werden
sowohl Änderungen an Spamhaus ASN-DROP als auch an den angekündigten
BGP-Präfixen beim nächsten Lauf übernommen.

## Voraussetzungen

Auf Debian/Ubuntu werden benötigt:

```sh
apt install iptables ipset curl util-linux gzip python3
```

`install.sh` prüft alle Pakete über `dpkg-query` und installiert nur fehlende
Pakete.

## Installation und erster Test

```sh
cd /pfad/zu/networkprotection
sudo ./install.sh
/opt/networkprotection/networkprotection.sh --version
sudo systemctl start networkprotection.service
```

Die Installation entfernt eine von älteren Projektversionen angelegte
`/etc/modules-load.d/networkprotection.conf`, sofern sie ausschließlich
`xt_geoip` enthält. Installierte xtables-addons-/DKMS-Pakete werden nicht
automatisch deinstalliert, da sie noch von anderen Anwendungen verwendet werden
könnten.

Den ersten Lauf in einer bestehenden SSH-Sitzung prüfen:

```sh
sudo systemctl status networkprotection.service
sudo journalctl -u networkprotection.service -n 100 --no-pager
sudo iptables -L INPUT -n --line-numbers
sudo iptables -L NETWORKPROTECTION -n -v
sudo ip6tables -L INPUT -n --line-numbers
sudo ip6tables -L NETWORKPROTECTION -n -v
sudo ipset list networkprotection_v4 | head
sudo ipset list networkprotection_geo_v4 | head
sudo ipset list networkprotection_asn_v4 | head
sudo ipset list networkprotection_asn_v6 | head
sudo systemctl list-timers networkprotection.timer
```

Erwartet werden in der IPv4-Chain bis zu drei kommentierte DROP-Regeln und in
der IPv6-Chain die ASN-DROP-Regel. In beiden `INPUT`-Chains steht der Sprung mit
dem Kommentar `networkprotection: entry` an Position 1.

## Konfiguration

Konfiguration und lokale Liste liegen nach der Installation hier:

```text
/etc/networkprotection/networkprotection.conf
/etc/networkprotection/custom-blacklist.txt
```

Wichtige Einstellungen:

```sh
ENABLE_IP_BLOCKLIST=yes
ENABLE_GEO_BLOCKLIST=yes
ENABLE_ASN_DROP=yes
BLOCK_COUNTRIES="CN,RU,IR,KP,BY,BR,IN,ID,VN,PK,BD,TH"
IPSET_NAME="networkprotection_v4"
GEOIP_SET_NAME="networkprotection_geo_v4"
ASN_DROP_V4_SET_NAME="networkprotection_asn_v4"
ASN_DROP_V6_SET_NAME="networkprotection_asn_v6"
ASN_DROP_RIPESTAT_WORKERS=4
```

Bestehende Konfigurationen aus früheren Versionen dürfen die nicht mehr
verwendeten Variablen `GEOIP_DB_DIR`, `GEOIP_DOWNLOADER` und `GEOIP_BUILDER`
noch enthalten; sie werden ignoriert. Neue ASN-DROP-Einstellungen sowie
`GEOIP_SET_NAME` und `GEOIP_DB_URL` erhalten automatisch sichere Standardwerte,
wenn sie in einer bestehenden Konfiguration fehlen.

Nach Änderungen:

```sh
sudo systemctl start networkprotection.service
```

## Migration

Nach einem erfolgreichen Test alte Cronjobs für `geo-blacklister.sh` und
`ip-blacklister.sh` deaktivieren. Alte `BLACKLIST`-Regeln und Sets werden nicht
automatisch entfernt.
