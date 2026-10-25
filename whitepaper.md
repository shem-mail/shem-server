# Zero-access opslag van e-mail

*Een architectuur voor een volledig versleutelde mailserver met doorzoekbare index, bedoeld voor zelf-gehoste omgevingen. Projectnaam: Shem (Self-Hosted Encrypted Mail). Conceptversie, oktober 2026.*

## 1. Samenvatting

Bestaande open-source mailstacks (Postfix met Dovecot, en nieuwere alternatieven zoals Stalwart) kunnen berichten versleuteld opslaan, maar laten de zoekindex of de metadata onversleuteld achter. Juist de index bevat de meest doorzoekbare weergave van je mail: woorden, afzenders, onderwerpen. Dit whitepaper beschrijft een architectuur waarin de volledige opslag van een mailbox, dus berichten, headers, mapstructuur en full-text index, uitsluitend versleuteld op schijf staat, met sleutels waar de systeembeheerder geen toegang toe heeft zodra de gebruiker zijn account in gebruik heeft genomen.

De kern van het ontwerp:

- Per mailbox één langlevend sleutelpaar. Binnenkomende mail wordt direct versleuteld met de publieke sleutel, zonder dat de gebruiker ingelogd hoeft te zijn.
- De privésleutel staat alleen versleuteld op schijf, beschermd door een sleutel die uit het wachtwoord van de gebruiker wordt afgeleid.
- Bij het inloggen via IMAP wordt de privésleutel tijdelijk in het geheugen van de server ontsleuteld. Dan pas wordt de achterstand aan nieuwe mail geïndexeerd.
- De index is een per-gebruiker Lucene-index op een eigen, versleutelende Directory-implementatie.
- De metadata van berichten (mappen, UID's, flags, datums en grootte) staat in een eigen versleutelde opslag per gebruiker: een append-only journaal met periodieke snapshots en een versleutelde indexstructuur op schijf. De berichten zelf zijn onveranderlijke, versleutelde bestanden. Daardoor is er geen leesbare mapstructuur en zijn back-ups eenvoudig.

Het resultaat beschermt tegen een duidelijk afgebakende groep aanvallers: iedereen die de opslag in uitgeschakelde of offline toestand in handen krijgt (diefstal, uitgefaseerde schijven, gelekte back-ups, snapshots zonder geheugen, een nieuwsgierige of onzorgvuldige beheerder zonder live-toegang). Het beschermt niet tegen een aanvaller die de draaiende machine controleert. Dat onderscheid loopt als een rode draad door dit document.

**Kernprincipe: zonder toegang tot de sleutels is niets van de mailbox leesbaar.** In de mailbox staan uitsluitend versleutelde bestanden: berichten, headers, bijlagen, mapnamen, flags en de zoekindex. De enige uitzondering is uitgaande mail die nog in de wachtrij staat (paragraaf 5.6). Wie de schijf, een back-up of een snapshot bezit, ziet van de mailbox alleen willekeurige gegevens. Dat geldt ook voor de systeembeheerder en de hostingaanbieder. De enige sleutel tot de inhoud wordt afgeleid van het wachtwoord van de gebruiker en bestaat alleen in het geheugen, zolang die gebruiker is ingelogd.

**Eén pakket.** Het ontwerp gaat uit van één zelfstandig Java-pakket dat SMTP (ontvangst en verzending), IMAP, DKIM-ondertekening en -validatie, spamfiltering en greylisting omvat, aangevuld met een webinterface voor accountbeheer en self-service wachtwoord- en sleutelbeheer. Er zijn dus geen losse programma's meer, zoals Postfix en Dovecot, waartussen leesbare data over schijf of socket wordt doorgegeven. Dat verkleint het aantal plekken waar mail onversleuteld kan achterblijven, maar maakt de bouwopgave groot.

**De naam: Shem.** Het project heet Shem, naar de joodse golemlegende. Een golem is een figuur van klei die tot leven komt door een *shem*: een strookje perkament met een goddelijke naam dat in zijn mond wordt gelegd. Wordt de shem weggenomen, dan is de golem weer levenloze klei. Dat beeld beschrijft de kern van dit ontwerp. Zonder de sleutel van de gebruiker is een mailbox niets meer dan onleesbare gegevens; pas bij het inloggen komt hij tot leven, en bij het uitloggen wordt hij weer klei. Er bestaat geen tweede shem bij de beheerder of op de server. Het Hebreeuwse woord *shem* betekent "naam"; de projectnaam verwijst naar de legende, niet naar het religieuze gebruik van het woord als aanduiding voor God. Daarnaast is SHEM een afkorting van Self-Hosted Encrypted Mail: versleutelde mail op een server die de gebruiker zelf beheert. De afkorting zegt bewust niets over zero-knowledge, omdat de server binnenkomende mail en ingelogde mailboxen wel kort in leesbare vorm verwerkt (zie paragraaf 6.2).

## 2. Aanleiding

### 2.1 Waarom e-mail zo gevoelig is

E-mail is voor veel mensen het meest complete archief van hun leven: contracten, facturen, medische correspondentie, wachtwoordherstelmails voor vrijwel alle andere accounts. Wie iemands mailbox kan lezen, kan meestal ook zijn andere accounts overnemen. Opslag van die gegevens in leesbare vorm bij een hostingpartij is dus een aanzienlijk risico, ook als de eigenaar van de server zelf te vertrouwen is.

### 2.2 Zelf hosten op gehuurde infrastructuur

Wie zelf een mailserver draait, doet dat vaak op een gehuurde VPS. Daarbij zijn er partijen met toegang tot de onderliggende opslag: de hostingaanbieder, diens beheerders, back-upsystemen en in het uiterste geval autoriteiten die een vordering indienen. Versleuteling van het volledige schijfvolume (LUKS of vergelijkbaar) helpt daar maar beperkt: het volume is ontsleuteld zolang de machine draait, en bij een VPS wordt de sleutel ingevoerd of bewaard op een systeem dat de aanbieder kan inspecteren.

### 2.3 Het tekort in de bestaande stack

Voor zover bekend uit de documentatie en de eigen verkenning van de auteur, is de situatie als volgt:

- **Postfix en Dovecot.** Dovecot heeft een plugin (mail-crypt) die berichten met een per-gebruiker sleutelpaar kan versleutelen. Dat dekt de berichtinhoud, maar de Dovecot-indexbestanden en caches, en de full-text-search-plugins (zoals Lucene-, Solr- of Xapian-gebaseerde varianten), slaan hun gegevens in leesbare vorm op. Daarmee lekt precies de informatie die je wilde beschermen. Bovendien staat de Postfix-wachtrij in leesbare vorm op schijf.
- **Stalwart.** Biedt versleuteling van opgeslagen berichten, maar de index is onvolledig beschermd (alleen headers, of niet versleuteld).
- **Versleuteld bestandssysteem per gebruiker** (bijvoorbeeld gocryptfs of fscrypt) zou in principe de hele Dovecot-opslag kunnen afschermen, maar vraagt om een oplossing voor binnenkomende mail op het moment dat de gebruiker niet is ingelogd. Daarover meer in paragraaf 7.

De conclusie is dat er geen kant-en-klare oplossing is die tegelijk (a) mail accepteert zonder dat de gebruiker is ingelogd, (b) alle opslag inclusief index versleutelt, en (c) server-side zoeken in de volledige tekst ondersteunt.

## 3. Doelen en niet-doelen

**Doelen**

1. Alle gebruikersgegevens at rest versleuteld: berichten, headers, bijlagen, mapnamen, flags, index.
2. Mail kan altijd worden ontvangen, ook als niemand is ingelogd.
3. Volledige server-side doorzoekbaarheid (IMAP SEARCH) zodra de gebruiker is ingelogd.
4. Zonder toegang tot de sleutels van de gebruiker is niets van de mailbox leesbaar: niet voor de beheerder, niet voor de hostingaanbieder en niet voor wie een kopie van de schijf of een back-up bezit. De beheerder kan de gegevens dus ook niet herstellen. Verlies van het wachtwoord betekent verlies van de gegevens.
5. Standaard IMAP-clients blijven werken zonder aanpassing.

**Niet-doelen**

1. Bescherming tegen een aanvaller met controle over de draaiende machine.
2. End-to-end-versleuteling tussen afzender en ontvanger. De mail komt gewoon via SMTP binnen.
3. Verbergen van het feit dát mail wordt uitgewisseld (verkeersmetadata op netwerkniveau).
4. Bescherming van uitgaande mail die nog in de wachtrij staat (paragraaf 5.6).

## 4. Dreigingsmodel

Het ontwerp is bedoeld voor de volgende aanvallers en gebeurtenissen:

| Scenario | Beschermd? |
| --- | --- |
| Schijf of VPS-image wordt gestolen, gekopieerd of na afloop van het contract niet goed gewist | Ja |
| Back-up of offsite-kopie lekt | Ja |
| Snapshot van het schijfvolume zonder geheugeninhoud | Ja |
| Beheerder of hostingmedewerker bekijkt bestanden terwijl niemand is ingelogd | Ja |
| Beheerder bekijkt bestanden terwijl een gebruiker is ingelogd | Gedeeltelijk: de sleutel staat in RAM |
| Snapshot van het werkgeheugen van de VPS (hypervisor) | Nee |
| Aanvaller met rootrechten die de software aanpast om wachtwoorden af te vangen | Nee |
| Zwak wachtwoord en offline raden met een gestolen schijf | Alleen zo sterk als het wachtwoord |
| Mail in transit en tijdens ontvangst via SMTP | Nee (buiten scope) |

Het model is dus: bescherming tegen **passieve, offline** aanvallers, niet tegen **actieve** aanvallers met live-toegang.

### 4.1 Wat een aanvaller zonder sleutels aantreft

Zonder het wachtwoord van de gebruiker (of de sleutel uit het geheugen van een draaiende server) is elk onderdeel van de mailbox onleesbaar. Alleen enkele technische kenmerken blijven zichtbaar.

| Onderdeel | Staat op schijf als | Leesbaar zonder sleutels? |
| --- | --- | --- |
| Berichtinhoud en bijlagen | Versleutelde blokken (AEAD) | Nee |
| Headers (afzender, onderwerp, datum) | Onderdeel van het versleutelde bericht | Nee |
| Mapnamen, flags, doelmap bij bezorging | Versleuteld metadata- en bezorgjournaal | Nee |
| Zoekindex (Lucene) | Versleutelde bestanden onder de indexsleutel | Nee |
| Privésleutel van de mailbox | Ingepakt onder een sleutel uit het wachtwoord | Nee |
| Berichtsleutels en indexsleutel | Ingepakt met de mailboxsleutel | Nee |
| Publieke sleutel | Onversleuteld | Ja, maar ontsleutelen kan er niet mee |
| Bestandsgroottes, aantallen, tijdstippen | Bestandssysteemmetadata | Ja (zie paragraaf 6.3) |
| Uitgaande mail in de wachtrij (tijdelijk) | Leesbare bestanden tot de aflevering | Ja (zie paragraaf 5.6) |

De enige weg naar de inhoud loopt dus via het wachtwoord van de gebruiker, of via het werkgeheugen van de draaiende server tijdens een sessie. Er is geen hoofdsleutel bij de beheerder, geen herstelmechanisme aan de serverkant en geen leesbare kopie van de index. Daar staat tegenover dat deze belofte even sterk is als het wachtwoord zelf (zie paragraaf 6.2).

## 5. Architectuur

### 5.1 Sleutelhiërarchie

Het ontwerp gebruikt de beproefde techniek van hybride versleuteling, zoals ook toegepast in OpenPGP, S/MIME, het hulpmiddel age en HPKE (RFC 9180):

- **Mailboxsleutelpaar.** Een asymmetrisch sleutelpaar per mailbox. De publieke sleutel staat onversleuteld op de server en wordt door de bezorgcomponent gebruikt. De privésleutel staat alleen versleuteld op schijf.
- **Berichtsleutel.** Per binnenkomend bericht wordt een willekeurige symmetrische sleutel gegenereerd (bijvoorbeeld voor AES-256-GCM of ChaCha20-Poly1305). Het bericht wordt hiermee versleuteld; de berichtsleutel zelf wordt met de publieke sleutel ingepakt en naast het bericht opgeslagen.
- **Wachtwoordsleutel (KEK).** Uit het wachtwoord van de gebruiker wordt met een memory-hard functie (Argon2id) een sleutel afgeleid die de privésleutel beschermt. Het wachtwoord wordt zonder aparte verificatiehash gecontroleerd: de privésleutel is ingepakt met een authenticated cipher, en klopt de authenticatietag bij het uitpakken, dan klopt het wachtwoord. Zo ligt er op schijf geen tweede gegeven waarmee een aanvaller offline wachtwoorden kan raden. Argon2id komt uit Bouncy Castle, omdat de JDK dat algoritme nog niet heeft.
- **Indexsleutel.** Een symmetrische sleutel waarmee de Lucene-index wordt versleuteld. Ook die wordt ingepakt met de mailboxsleutel en bestaat dus nooit onversleuteld op schijf.

De keuze voor het aantal bits verdient een kanttekening. Een asymmetrisch paar op een elliptische kromme (X25519) biedt bij veel kleinere sleutels een veiligheid die vergelijkbaar is met RSA-3072. Omdat mail vaak decennia bewaard blijft, is het raadzaam om vanaf het begin een hybride post-quantum-variant (bijvoorbeeld X25519 gecombineerd met ML-KEM) te overwegen. Een aanvaller kan versleutelde mail nu kopiëren en later ontsleutelen: harvest now, decrypt later.

Belangrijk: gebruik bestaande, gestandaardiseerde formaten en beproefde bibliotheken (bijvoorbeeld Google Tink of Bouncy Castle voor Java) en verzin geen eigen cryptografische constructies. Het eigen werk zit in de architectuur, niet in de primitieven.

### 5.2 Binnenkomende mail

1. De SMTP-server van het pakket accepteert de verbinding. Bij een onbekende combinatie van afzender, verzendend IP-adres en ontvanger kan greylisting een tijdelijke weigering (4xx) geven.
2. Tijdens de SMTP-dialoog worden SPF-, DKIM- en DMARC-controle, spamfiltering, virusscan en gebruikersregels (zoals Sieve) uitgevoerd, in het geheugen op leesbare tekst, vóór de versleuteling. Het resultaat, zoals de doelmap, wordt als metadata vastgelegd.
3. Het bericht wordt in een stroom (streaming AEAD, in blokken) versleuteld met een nieuwe berichtsleutel, en die sleutel wordt met de publieke sleutel ingepakt. Doelmap en flags worden ook met de publieke sleutel versleuteld opgeslagen in een bezorgjournaal.
4. Pas daarna bevestigt de SMTP-server de ontvangst aan de afzender (250 OK). Mislukt het wegschrijven, dan volgt een tijdelijke weigering en probeert de afzender het later opnieuw.

Doordat SMTP, filtering en opslag in één pakket draaien, bestaat er geen leesbare tussenopslag: er is geen wachtrij op schijf waarin het bericht onversleuteld staat. Het bericht leeft alleen in het geheugen totdat het versleuteld is weggeschreven. Bij een opzet met losse programma's kan elke overdracht, bijvoorbeeld van de MTA naar een bezorgprogramma, een extra leesbare kopie achterlaten. Uitgaande mail en logbestanden vragen dezelfde zorg, zie paragraaf 5.6 en 6.3.

### 5.3 Inloggen en indexeren

Bij een IMAP-login gebeurt het volgende:

1. Uit het wachtwoord wordt met Argon2id de KEK afgeleid.
2. Met de KEK wordt de ingepakte privésleutel ontsleuteld. Klopt de authenticatietag, dan is het wachtwoord juist; een aparte verificatiehash is er niet. De privésleutel blijft alleen in het geheugen van de sessie.
3. Het bezorgjournaal wordt verwerkt: berichtsleutels worden uitgepakt, mappen en flags bijgewerkt, en de nieuwe berichten toegevoegd aan de index.
4. Optioneel wordt de uitgepakte berichtsleutel daarna opnieuw ingepakt met een snelle symmetrische mailboxsleutel. Dat bespaart bij elke volgende leesactie een asymmetrische bewerking.
5. Bij uitloggen van de laatste sessie worden alle sleutels uit het geheugen gewist.

**Foutieve aanmeldpogingen begrenzen.** Elke poging kost een volledige Argon2id-run, dus het aantal pogingen bepaalt zowel hoe snel iemand wachtwoorden kan raden als hoeveel belasting de server krijgt. Begrens foutieve pogingen daarom per IP-adres, voor IMAP, SMTP-submission en de webinterface samen, met oplopende vertraging of een tijdelijke blokkade van dat adres. Het voordeel is dat een aanvaller een gebruiker niet kan buitensluiten: de echte gebruiker komt vanaf het eigen adres gewoon binnen. De keerzijde is dat een aanvaller die vanaf veel adressen tegelijk probeert, per adres onder de grens blijft. Vang dat op met een plafond voor het aantal gelijktijdige Argon2id-berekeningen, zodat de server niet kan worden overbelast. Behandel onbekende gebruikersnamen op dezelfde manier, zodat niet te zien is of een account bestaat. Houd de tellers in het geheugen: ze zeggen wie wanneer heeft geprobeerd in te loggen. Deze begrenzing beschermt alleen tegen online raden. Tegen offline raden met een schijfkopie helpt alleen een sterk wachtwoord met een zware Argon2id-instelling (paragraaf 6.2).

Tot het moment van indexeren is de index niet volledig. Een IMAP SEARCH-opdracht zou dan onvolledige resultaten geven. De oplossing is eenvoudig: zoek in de index en doorzoek daarnaast met brute kracht de (meestal kleine) set nog niet geïndexeerde berichten. Zo blijven resultaten correct.

Een praktisch vraagstuk is dat IMAP-clients zoals telefoons en mailapps met een app-wachtwoord werken. Een goede oplossing zijn **sleutelslots**, zoals bij LUKS: de privésleutel wordt meerdere keren ingepakt, één keer per wachtwoord of app-wachtwoord. Dan kunnen meerdere apparaten tegelijk werken, en kan een app-wachtwoord worden ingetrokken zonder de rest aan te raken. Een herstelcode (een lang, willekeurig geheim dat de gebruiker offline bewaart) kan een extra slot vormen.

### 5.4 De versleutelde Lucene-index

Lucene is een goede kandidaat omdat de opslag achter een abstractielaag zit, de `Directory`. Alle bestanden van de index gaan daar doorheen. Een eigen implementatie (bijvoorbeeld een `FilterDirectory` rond een gewone `FSDirectory`) kan elk bestand versleuteld wegschrijven en versleuteld teruglezen.

Belangrijke ontwerpkeuzes:

- **Segmentbestanden zijn write-once.** Lucene schrijft een bestand eenmaal en past het daarna niet meer aan. Dat past goed bij versleuteling met een unieke sleutel of nonce per bestand.
- **Willekeurige leestoegang.** Lucene springt met seek door bestanden. Een gewone stroomversleuteling (zoals een lange GCM-stroom) is daarvoor ongeschikt. Gebruik blokgewijze authenticated encryption (bijvoorbeeld blokken van 4 tot 16 KB, elk met een eigen nonce afgeleid van bestandsnummer en blokindex), of AES-CTR met een aparte integriteitscontrole per bestand.
- **Geen memory mapping.** Normaal gebruikt Lucene mmap voor snelheid. Dat werkt niet op versleutelde data. De implementatie heeft een eigen cache van ontsleutelde blokken nodig, in het geheugen van het proces, met een begrensde grootte.
- **De index is afgeleide data.** Als de index beschadigd raakt of de sleutel wordt geroteerd, kan hij volledig worden herbouwd uit de berichten. Dat maakt de index tot een cache en vereenvoudigt sleutelrotatie en herstel.
- **Bijlagen.** Tekstextractie uit bijlagen gebeurt met Apache Tika, in een afgeschermd proces met minimale rechten (zie het blok over bijlagen hieronder).

Houd er rekening mee dat een volledige tekstindex aanzienlijk is: in de orde van tientallen procenten van de ruwe tekst, afhankelijk van analyzers en opgeslagen velden. Ook een versleutelde index lekt nog iets: bestandsgroottes, aantallen segmenten en het tijdstip van wijzigingen zeggen iets over omvang en activiteit van een mailbox. Dat is een bewust geaccepteerd restrisico.

**Versleuteling in de applicatie of in het besturingssysteem.** De index kan ook door het besturingssysteem worden versleuteld, bijvoorbeeld met fscrypt, dat sleutels per map kent. De [documentatie van de Solr-encryptiemodule](https://apache.googlesource.com/solr-sandbox/+/55aa6fa8c90e0c550c2485dba787245b6c94adba/ENCRYPTION.md) raadt dat aan wanneer het kan, omdat het sneller is en beter samenwerkt met de bestandscache van het besturingssysteem. Dit ontwerp kiest toch voor versleuteling in de applicatie:

- **Verhuisbaar.** Een mailbox bestaat uit versleutelde bestanden die zonder bijzondere kernel- of bestandssysteemeigenschappen naar een andere server, hostingaanbieder of besturingssysteem kunnen worden gekopieerd. Bij versleuteling op OS-niveau hangt een migratie af van de kernel, het bestandssysteem en de configuratie van de doelmachine.
- **Geen afhankelijkheid van de host.** Het beveiligingsmodel hoeft niet te veranderen als een VPS-aanbieder bepaalde kernelfuncties niet toestaat.
- **Tegen root geen verschil.** Ook bij versleuteling op OS-niveau is de data leesbaar voor root zodra de sleutel is geladen (zie paragraaf 6.2).

De prijs is prestatie: volgens de Solr-documentatie ongeveer 20% bij de meeste zoekopdrachten en 60% bij zoekopdrachten met meerdere termen (zie paragraaf 9). Voor een migratie blijven de serverbrede geheimen en instellingen over, zoals DKIM- en TLS-sleutels, DNS en de reputatie van het IP-adres. Geef het opslagformaat verder een versienummer, zodat het later kan worden gemigreerd.

**Bijlagen indexeren.** Voor tekstextractie uit bijlagen wordt Apache Tika gebruikt. Het herkent het bestandstype en haalt de tekst uit gangbare formaten: PDF, Word (.doc en .docx), Excel, PowerPoint, OpenDocument, RTF, platte tekst, HTML en CSV, plus ingesloten e-mailberichten. Voor PDF en Office-bestanden gebruikt Tika onder meer PDFBox en Apache POI. Tika werkt rechtstreeks op een stream, dus de ontsleutelde bijlage kan vanuit het geheugen worden aangeboden. Voor de uitvoering gelden deze regels:

- **Apart proces.** Voer de extractie uit in een onderprivilegieerd proces zonder netwerktoegang, met limieten voor tijd en geheugen. Tika biedt daarvoor een ForkParser met instelbare time-out en een tika-server. Een kwetsbaarheid in een parser blijft zo buiten het hoofdproces met de sessiesleutels.
- **Tijdelijke bestanden op tmpfs.** Voor formaten die willekeurige toegang nodig hebben, kan Tika een stream naar een tijdelijk bestand kopiëren (te verifiëren in de spike). In de standaard tijdelijke map zou de ontsleutelde bijlage dan leesbaar op schijf staan. Wijs die map daarom aan naar tmpfs of een RAM-schijf.
- **Limieten.** Begrens de hoeveelheid tekst per bijlage en de diepte van ingesloten bestanden, zoals ZIP-archieven, tegen decompressiebommen.
- **Alleen tekst.** Indexeer de tekst en sla die niet op in Lucene.
- **Buiten bereik.** Wachtwoordbeveiligde bestanden kunnen niet worden geïndexeerd. OCR voor gescande bestanden is geen Java-only functie en valt buiten dit ontwerp. Een externe tool als Tesseract is een mogelijke latere uitbreiding.

### 5.5 Eén pakket: componenten en protocollen

Het pakket bevat alle onderdelen van de mailketen in één Java-toepassing. Daardoor gaat leesbare data nooit via een wachtrij op schijf of een lokale socket van het ene programma naar het andere. De onderdelen:

- **SMTP-ontvangst** (poort 25): accepteert mail van andere servers, met greylisting, rate limiting, SPF-, DKIM- en DMARC-controle, spam- en virusfiltering en versleutelde bezorging (paragraaf 5.2).
- **SMTP-submission** (poort 587 en 465): gebruikers verzenden hier hun mail, na authenticatie met begrensde foutieve pogingen per IP-adres (paragraaf 5.3). Hier vindt ook de DKIM-ondertekening plaats (paragraaf 5.6).
- **Uitgaande bezorging**: een eigen wachtrij met herhaalpogingen, bouncebehandeling en TLS-afdwinging (MTA-STS, DANE).
- **IMAP** (poort 993): toegang voor mailclients, inclusief SEARCH via de versleutelde index. Foutieve aanmeldpogingen worden per IP-adres begrensd (paragraaf 5.3).
- **Opslag- en indexlaag**: de versleutelde berichtopslag, het bezorgjournaal en de Lucene-index (paragraaf 5.1 tot en met 5.4).
- **Webinterface**: accountbeheer en self-service wachtwoord- en sleutelbeheer (paragraaf 5.8).
- **Certificaatbeheer en HTTP-endpoint** (poort 80 en 443): vraagt en vernieuwt TLS-certificaten bij Let's Encrypt en beantwoordt daarvoor de HTTP-uitdaging (paragraaf 5.11).

Dit is een grote bouwopgave. SMTP, IMAP en DKIM zijn volwassen standaarden met veel randgevallen, en interoperabiliteit met echte clients en mailservers kost veel testwerk. Voor de protocollagen en de mailboxabstractie wordt gebouwd op modules van het Apache James-project, in een eigen applicatie en niet op de James-server zelf (paragraaf 5.9). De opslaglaag blijft in alle gevallen strikt gescheiden van de protocollagen, zodat de versleuteling op één plek wordt afgedwongen.

### 5.6 DKIM, SPF, DMARC en uitgaande mail

**DKIM-ondertekening.** Uitgaande mail wordt bij submission ondertekend met een domeinsleutel. Die sleutel hoort bij het domein, niet bij een gebruiker, en moet door de server zonder tussenkomst van een gebruiker kunnen worden gebruikt. Het is daarmee een geheim dat de server zelfstandig moet kunnen gebruiken, net als de TLS-sleutel. Compromittering ervan laat een aanvaller mail namens het domein ondertekenen, maar geeft geen toegang tot de inhoud van mailboxen. Bewaar de domeinsleutel als bestand dat alleen leesbaar is voor het serviceaccount van het pakket, zoals bij gangbare DKIM-software, zonder wachtwoord of sleutelkluis. Een wachtwoord dat bij elke start moet worden ingevoerd, beschermt niet tegen root, die de sleutel uit het geheugen kan lezen. Beperk de schade van een lek op andere manieren: roteer selectors regelmatig, houd de TTL van de DNS-records kort zodat een gelekte sleutel snel ongeldig is gemaakt, en volg de DMARC-rapporten om misbruik te zien. Een kopie van de schijf of een back-up geeft de sleutel wel prijs aan een offline aanvaller, omdat hij buiten de mailboxversleuteling valt. Bewaar back-ups van dit bestand daarom versleuteld. RSA-2048 is de veilige keuze voor brede ontvangstcompatibiliteit; Ed25519 kan als tweede handtekening worden toegevoegd.

**Validatie bij ontvangst.** SPF, DKIM en DMARC worden tijdens de SMTP-dialoog gecontroleerd. De uitkomst wordt als Authentication-Results-header in het bericht opgenomen vóór de versleuteling en maakt dus zelf deel uit van het versleutelde bericht. Voor doorgestuurde mail kan ARC worden ondersteund.

**De uitgaande wachtrij is een eerlijke beperking.** Een bericht dat naar een andere server gaat, moet de server in leesbare vorm kunnen verwerken, ook als de gebruiker inmiddels is uitgelogd en de verzending moet worden herhaald. De uitgaande wachtrij kan dus niet onder de sleutel van de gebruiker staan. Praktische aanpak: de wachtrij wordt niet versleuteld. Dit is een bewuste uitzondering op het kernprincipe: mail die nog onderweg is, staat tot de aflevering leesbaar op schijf, ook voor een offline aanvaller. Bewaartermijn en herhaalpogingen volgen de gebruikelijke waarden, en items worden na aflevering verwijderd. Het beschermen van uitgaande mail in de wachtrij is geen doel van dit project. De kopie in Verzonden wordt wel versleuteld met de publieke sleutel van de gebruiker. Mail aan een andere gebruiker op dezelfde server komt de wachtrij niet in en wordt direct versleuteld bezorgd. De ontvangende server van een extern adres krijgt de mail sowieso leesbaar; dat valt buiten wat dit ontwerp kan beschermen.

### 5.7 Spamfiltering, greylisting en virusscan

Beide moeten werken op het moment van ontvangst, dus zonder dat de gebruiker is ingelogd. Dat beperkt wat ze kunnen doen en wat ze mogen bewaren.

**Greylisting** bewaart per combinatie van afzender, verzendend IP-adres en ontvanger een tijdstip. Die gegevens vertellen wie met wie mailt. Bewaar ze daarom uitsluitend in het geheugen, met een korte bewaartermijn, en nooit op schijf. Verlies van de database na een herstart is acceptabel: afzenders worden dan alleen opnieuw kort uitgesteld.

**Spamfiltering** is bewust eenvoudig en niet zelflerend. De basiscontroles hebben geen mailinhoud nodig: SPF, DKIM en DMARC, aangevuld met eenvoudige controles zoals de reputatie van het IP-adres en protocolafwijkingen. Die draaien bij ontvangst; externe opzoekingen laten alleen verbindingsgegevens zien aan derden, geen inhoud. Overige spam wordt vooral tegengehouden met greylisting, aangevuld met een eenvoudige inhoudscontrole die alleen tagt (zie hieronder). Er is geen inhoudsfilter dat van de mail van gebruikers leert, en daarmee ook geen model dat inhoud moet bewaren of onder een gebruikerssleutel moet worden getraind. Dat past bij het uitgangspunt dat de server geen leesbare mailinhoud verzamelt.

**Inhoudscontrole zonder leren.** Een eigen, kleine regelmotor in Java beoordeelt het bericht bij ontvangst, in het geheugen en vóór de versleuteling. De regels staan in een bijwerkbaar bestand met gewogen trefwoorden, zinsdelen, reguliere expressies en headercontroles, en de som van de scores bepaalt of het bericht wordt getagd. Een getagd bericht komt via het bezorgjournaal in de Spam-map. Het wordt nooit geweigerd, omdat een filter zonder leren zowel valse alarmen als gemiste spam geeft. De regels kunnen zonder herstart worden bijgewerkt. Voor het testen van de keten bestaat de GTUBE-teststring van SpamAssassin.

Het zwakke punt is de regelbron. Er is geen onderhouden Java-motor gevonden met een eigen, continu bijgewerkte regelset. Mogelijkheden zijn zelf onderhouden regels, of het importeren van een eenvoudige deelverzameling van de regelbestanden van SpamAssassin (alleen body- en headerregels). Scores uit zulke regelbestanden kunnen niet zonder meer worden overgenomen, omdat ze zijn afgesteld op de volledige regelset.

**Optionele koppeling met SpamAssassin of Rspamd.** Wie betere herkenning wil, kan het bericht bij ontvangst door een lokale SpamAssassin- of Rspamd-daemon laten beoordelen en de score voor dezelfde tag gebruiken. Dat wijkt af van het eenpakketprincipe en voert leesbare mail over een lokale socket, dus het blijft optioneel. Zet leren (Bayes, fuzzy-opslag) uit, zodat de daemon geen statistieken over mailinhoud bewaart. Zet ook externe opzoekingen uit die inhoud lekken, zoals URIBL's en diensten die hashes van de inhoud versturen (Razor, Pyzor, DCC).

**Virusscan.** Er is geen volwassen Java-only virusscanner met open handtekeningendata gevonden. Het project [Traditional-Antivirus](https://github.com/Konloch/Traditional-Antivirus) is een Java-implementatie die de ClamAV-database gebruikt. Het meldt zelf dat het nog in ontwikkeling is, dat de scanmethoden minder geavanceerd zijn dan die van ClamAV, en adviseert ClamAV wanneer een stabiele scanner nodig is. De scan vindt plaats bij ontvangst, in het geheugen en vóór de versleuteling, omdat de server daarna tot de volgende login niets meer kan lezen. Wat er met een gevonden virus gebeurt (taggen, quarantaine of weigeren), is een configuratiekeuze. Het ontwerp kent twee lagen:

- **Standaard: eigen basiscontrole.** Een Java-component zonder handtekeningendatabase die gevaarlijke bijlagen herkent: uitvoerbare bestanden en scripts (zoals .exe, .scr, .js en .vbs), dubbele extensies zoals .pdf.exe, en Office-bestanden met macro's. Het herkennen van macro's kan mogelijk met Apache POI (te verifiëren in de spike).
- **Optioneel: ClamAV via clamd.** Een native daemon met een open handtekeningendatabase die meerdere keren per dag wordt bijgewerkt via freshclam. Een Java-client kan het bericht als stream aanbieden (de INSTREAM-opdracht van clamd), zonder tijdelijk bestand op schijf. Dat wijkt af van het eenpakketprincipe en voert leesbare mail over een lokale socket, dus het blijft optioneel. ClamAV laadt de hele database in het geheugen, in de orde van een gigabyte of meer, wat op een kleine VPS meetelt.

Dit heeft beperkingen. Een geslaagde SPF-, DKIM- of DMARC-controle zegt dat de afzender is wie hij zegt te zijn, niet dat de mail gewenst is. Spam van afzenders die deze controles doorstaan, komt dus binnen. Greylisting houdt alleen afzenders tegen die het niet opnieuw proberen, en vertraagt de eerste mail van een nieuwe afzender. Gebruikersregels (paragraaf 5.2) kunnen aanvullend filteren.

### 5.8 Webinterface en self-service sleutelbeheer

De webinterface kent twee rollen met strikt gescheiden rechten.

- **Beheerder**: domeinen, accounts en aliassen aanmaken, quota instellen, accounts blokkeren of verwijderen, DKIM-selectors roteren en de benodigde DNS-records tonen. De beheerder kan geen wachtwoord herstellen en geen inhoud inzien. Een vergeten wachtwoord is alleen op te lossen door het account leeg opnieuw aan te maken.
- **Gebruiker**: de self-service acties uit onderstaande tabel.

| Actie | Wat er met de sleutels gebeurt | Effect op berichten en index |
| --- | --- | --- |
| Wachtwoord wijzigen | De privésleutel wordt opnieuw ingepakt onder het nieuwe wachtwoord | Geen |
| App-wachtwoord aanmaken of intrekken | Een sleutelslot wordt toegevoegd of verwijderd | Geen |
| Herstelcode genereren | Extra sleutelslot onder een lang, willekeurig geheim | Geen |
| Sleutelrotatie (nieuw sleutelpaar) | Nieuw paar; berichtsleutels en indexsleutel worden opnieuw ingepakt; het oude paar wordt vernietigd | Berichten zelf blijven staan; kopieën van oudere data blijven met de oude sleutel leesbaar |
| Account verwijderen | Alle ingepakte sleutels worden gewist | Data is onbruikbaar (crypto-erase); kopieën in back-ups blijven leesbaar voor wie het wachtwoord kent, tenzij ze ook worden gewist |
| Export | De sessiesleutel ontsleutelt tijdens de download | Versleutelde of leesbare export naar keuze, bijvoorbeeld MBOX |

De webinterface valt onder hetzelfde vertrouwensmodel als IMAP: het wachtwoord passeert de server. Sleutelafleiding in de browser (bijvoorbeeld Argon2 in WebAssembly) lijkt de server buiten te sluiten, maar beschermt niet tegen een server die kwaadaardige JavaScript levert, en wordt hier dus niet als zekerheid gepresenteerd. Beveilig sessies en formulieren op de gebruikelijke manier: CSRF-bescherming, korte sessieduur, begrenzing van aanmeldpogingen per IP-adres (paragraaf 5.3) en twee-factorauthenticatie voor de web-login. Een tweede factor beschermt de online toegang, maar niet tegen het offline raden van het wachtwoord, tenzij de tweede factor zelf sleutelmateriaal bijdraagt, bijvoorbeeld via WebAuthn-extensies voor sleutelafleiding (PRF; ondersteuning verschilt per apparaat). Dat is een kandidaat voor vervolgonderzoek.

### 5.9 Technische basis: Apache James-modules in een eigen applicatie

Het ontwerp bouwt niet voort op de James-server zelf. Het hergebruikt alleen de protocol- en mailboxmodules van het Apache James-project, binnen een eigen applicatie met een eigen versleutelde opslag. Deze keuze volgt uit een vergelijking van drie niveaus van hergebruik.

| Niveau | Wat wordt hergebruikt | Wat wordt zelf geschreven | Oordeel |
| --- | --- | --- | --- |
| 1. Volledige James-server met eigen opslagmodule | Alles: protocollen, mailet-pipeline, wachtrij, gebruikersbeheer, WebAdmin | Opslagmodule en sleutelbeheer | Verworpen: erft veel onderdelen die leesbare data aannemen, zoals de mailwachtrij |
| 2. Protocol- en mailboxmodules in een eigen applicatie | IMAP- en SMTP-protocollagen, mailbox-API, bibliotheken als Mime4J, jSPF en jDKIM | Mailbox-backend, wachtrij, gebruikers- en sleutelbeheer, bedrading, webinterface | Gekozen |
| 3. Alleen losse bibliotheken | Parsing, SPF, DKIM | Alle protocollagen, inclusief IMAP | Verworpen: IMAP is het grootste en lastigste onderdeel |

**Waarom niveau 2.** Zo erft de applicatie zo weinig mogelijk onderdelen die leesbare data kunnen aannemen, zonder dat IMAP zelf moet worden gebouwd. De mailbox-implementaties van het project zijn volgens de [README van het mailboxproject](https://apache.googlesource.com/james-project/+show/master/mailbox/README.md) los van de James-server te gebruiken. De eigen versleutelde backend komt in de plaats van de bestaande JPA-, Cassandra- of Postgres-implementaties. Dat is het uitbreidingspunt waarvoor de mailbox-API bedoeld is. Ter vergelijking: in de JPA-variant van de server draait de mailwachtrij op ActiveMQ (zie de [packaging-pagina](https://james.apache.org/server/packaging.html)): een tussenopslag die dit ontwerp juist niet wil.

**Wat zelf wordt geschreven.**

- De mailbox-backend: een implementatie van de mailbox-API die berichten, headers, mapnamen, flags en metadata versleuteld per gebruiker bewaart.
- Sessiebeheer: ontgrendelen van de privésleutel bij de IMAP-login en wissen bij uitloggen (paragraaf 5.3).
- Het bezorgjournaal en de bezorgcomponent die met alleen de publieke sleutel werkt (paragraaf 5.2).
- De uitgaande wachtrij, onversleuteld en kortlevend (paragraaf 5.6).
- Gebruikers- en domeinbeheer met sleutelslots, plus de webinterface (paragraaf 5.8).
- Greylisting en spamfiltering (paragraaf 5.7).
- De versleutelde Lucene-Directory (paragraaf 5.4).

**Opslag zonder verplichte database.** De applicatie draait als één proces met bestanden, zonder Postgres of een andere externe dienst. Per gebruiker komt één versleutelde store in een eigen map. Dat geeft sleutelisolatie: een account verwijderen is de map wissen, en er zijn geen globale tabellen waaruit af te lezen is wie welke mappen en hoeveel berichten heeft. De metadata wordt bijgehouden als append-only journaal met periodieke snapshots (paragraaf 5.10), versleuteld met het sleutelmateriaal van de mailbox. Een embedded database is daarvoor niet nodig. De James-server zelf dwingt Postgres overigens niet af: de JPA-variant gebruikt standaard een ingebouwde Derby-database.

**Voorbehouden.**

- Een zelf samengestelde combinatie van James-componenten is volgens het project een ongeteste en niet-ondersteunde server. Reken dus op eigen interoperabiliteitstests. Het project heeft een eigen protocoltestsuite (MPT); controleer of die los tegen een eigen backend te draaien is.
- James gebruikt een eigen programmeermodel (Guice voor afhankelijkheden, een reactieve stijl) en vereist sinds versie 3.9 Java 21. Wie modules hergebruikt, erft die keuzes en moet updates blijven volgen.
- Het project lijkt zijn aandacht te verleggen naar de Postgres- en gedistribueerde varianten. Controleer hoe actief de modules zijn waarop je steunt.
- De licentie, Apache 2.0, staat gebruik en aanpassing toe.
- Het onderhoud van de protocollagen en hun beveiligingsupdates voor SMTP en IMAP wordt deels gedragen door het James-project, zolang de gebruikte modules worden bijgewerkt. Nieuwe protocolextensies die James niet biedt, en alles wat zelf is gebouwd (mailbox-backend, wachtrij, greylisting, sleutelbeheer, webinterface), blijft eigen onderhoud. Dat is een gevolg van de keuze voor eigen serversoftware.

**Eerste stap: een spike.** Voordat de keuze definitief is, moeten twee vragen worden beantwoord: draaien de IMAP-modules tegen een eigen mailbox-backend buiten de serverapplicatie, zonder dat veel serverstructuur meekomt? En hoeveel van de mailbox-API geeft headers en metadata in leesbare vorm terug, zodat die in de versleutelde store moeten passen? Valt de uitkomst tegen, dan is niveau 1 of 3 het alternatief.

### 5.10 Opslagmodel: onveranderlijke berichten, veranderlijke metadata

Berichten worden als afzonderlijke, onveranderlijke bestanden opgeslagen. Alles wat verandert, staat in een aparte metadata-opslag. Fysieke mappen per IMAP-folder en gecombineerde bestanden zoals mbox, die bij elke wijziging opnieuw worden geschreven, worden vermeden.

**Berichten.** Elk bericht is één versleuteld bestand, één keer geschreven en daarna nooit meer aangepast. De bestandsnaam is een willekeurige ID die niet van de inhoud is afgeleid, zodat de naam niets verraadt. Bestanden staan gespreid in submappen op basis van de eerste tekens van de ID, bijvoorbeeld `/aa/bd/aabd….ext`, zodat er nooit duizenden bestanden in één map staan. Doordat bestanden niet meer wijzigen, zijn back-ups eenvoudig: alleen nieuwe bestanden hoeven mee.

**Metadata.** Per gebruiker één versleutelde opslag, bijgehouden als append-only journaal met periodieke snapshots. Die bevat drie soorten gegevens:

- Folders: naam, UIDVALIDITY, UIDNEXT, HIGHESTMODSEQ, abonnement en speciale rol (Sent, Trash, Junk).
- Per bericht in een folder: UID, verwijzing naar het bestand, flags, interne datum, grootte en modseq.
- Een vooraf berekende samenvatting (envelope, bodystructure), zodat clients hun lijsten kunnen opbouwen zonder berichtbestanden te lezen.

Folders zijn dus rijen in de metadata, geen mappen op schijf. Een folder hernoemen is één regel aanpassen. Een bericht kopiëren of verplaatsen is een nieuwe rij met een nieuwe UID die naar hetzelfde bestand wijst, omdat IMAP per folder een eigen UID vraagt. Het bestand wordt pas verwijderd als geen enkele rij er nog naar verwijst, bij voorkeur met een korte uitstelperiode na EXPUNGE.

**Indexstructuur op schijf.** De metadata wordt tijdens een sessie niet volledig in het geheugen gehouden. Folders, UID's en flags worden opgezocht via een versleutelde indexstructuur op schijf, per gebruiker, zodat een grote mailbox niet geheel hoeft te worden geladen. Een geheugencache bewaart alleen de recent gebruikte delen. De indexstructuur volgt dezelfde regel als de rest van het opslagmodel: afgesloten, onveranderlijke bestanden die bij een nieuw snapshot worden samengevoegd of vervangen.

**Zelf bouwen of een bibliotheek.** Er bestaan Java-bibliotheken die zelf versleutelen, maar op hun eigen manier. [Xodus](https://github.com/JetBrains/xodus/wiki/Database-Encryption), een transactionele key-value store met logstructurele opslag, versleutelt met Salsa20 of ChaCha20 en kent eigen cipher-implementaties. Volgens een derde partij is het project wel in de sunset-fase beland, dus controleer de actuele onderhoudsstatus. H2 MVStore, een pure-Java key-value store in één bestand, heeft een instelbare sleutel en een configureerbare bestandsopslag. Het is echter één groot bestand dat blijft veranderen. Native opties zoals RocksDB en LMDB vallen af, omdat ze geen Java-only oplossing zijn.

De ingebouwde versleuteling van deze bibliotheken gebruikt één sleutel voor de hele database en bevat geen integriteitscontrole, dus ze past niet vanzelf bij de sleutelhiërarchie van paragraaf 5.1. Er zijn twee wegen: de pluggable laag van een bibliotheek gebruiken om met een eigen versleutelde bestandslaag te werken, of de gesorteerde segmentstructuur zelf bouwen op de afgesloten bestanden die het ontwerp toch al heeft. Het ontbreken van integriteitscontrole is op te lossen met een MAC per afgesloten segment. De keuze wordt beantwoord in de spike (paragraaf 5.9).

**Flags en zoeken.** Flags (\\Seen, \\Flagged, \\Deleted en eigen keywords) staan alleen in de metadata, want dat zijn de gegevens die makkelijk kunnen wijzigen. Een Lucene-document is onveranderlijk en wijzigen betekent opnieuw toevoegen, dus flags worden niet in de index opgenomen. Zoekopdrachten op flags worden uit de metadata beantwoord en gecombineerd met de UID-resultaten uit Lucene.

**Bezorgjournaal.** Het journaal uit paragraaf 5.2 heeft dezelfde vorm als de metadata (bericht in folder met flags). Bij het inloggen worden nieuwe regels in de metadata opgenomen, zodat er geen tweede mechanisme nodig is.

**Back-up en verwijderen.** De metadata is het enige deel dat vaak verandert, maar het is klein: in de orde van megabytes per gebruiker, en alleen bij zeer grote mailboxen enkele honderden megabytes. Het journaal bestaat uit afgesloten, versleutelde segmenten die niet meer wijzigen, met periodiek een snapshot van de volledige toestand. De actuele toestand is het laatste snapshot plus de segmenten daarna. Een back-up bestaat uit het nieuwste snapshot en de nieuwe segmenten, en is vanzelf consistent omdat afgesloten segmenten en snapshots niet meer veranderen. Alleen het segment waarin op dat moment wordt geschreven, hoort niet in de back-up. Een bericht onleesbaar maken kan door de ingepakte berichtsleutel uit de metadata te verwijderen. Omdat het journaal oude regels bewaart, werkt dat pas zodra een nieuw snapshot de oude segmenten heeft vervangen en die zijn verwijderd. Bestaande back-ups behouden de oude metadata en dus de sleutel.

### 5.11 TLS en certificaten via Let's Encrypt

Alle diensten die wachtwoorden of mail ontvangen, gebruiken TLS, met certificaten die het pakket zelf aanvraagt en vernieuwt bij Let's Encrypt.

**Waar TLS geldt.**

- IMAP (poort 993) en SMTP-submission (poort 465, en 587 met STARTTLS): TLS is verplicht vóór de authenticatie. Omdat het wachtwoord de server bereikt (paragraaf 6.2), mag inloggen zonder TLS nooit worden toegestaan.
- Webinterface: HTTPS.
- SMTP-ontvangst (poort 25): STARTTLS wordt aangeboden. Verplicht stellen kan niet, omdat niet alle andere servers het ondersteunen. Een MTA-STS-beleid kan afzenders vragen TLS af te dwingen. Dat beleid wordt via HTTPS geserveerd en kan dus door hetzelfde HTTP-endpoint worden aangeboden.

**Certificaten aanvragen en vernieuwen.** Het pakket bevat een ACME-client. Voor Java bestaan daar bibliotheken voor, zoals acme4j (te verifiëren). Het HTTP-endpoint op poort 80 beantwoordt de HTTP-01-uitdaging van Let's Encrypt en verwijst al het overige verkeer door naar HTTPS. Het endpoint serveert verder niets, om het aanvalsoppervlak klein te houden. Alternatieven zijn TLS-ALPN-01 (poort 443) en DNS-01, dat toegang tot de DNS-server vraagt en nodig is voor wildcards. Let's Encrypt werkt aan een nieuwe uitdaging, DNS-PERSIST-01, verwacht in 2026, waarbij een vast DNS-record volstaat in plaats van een nieuw record bij elke vernieuwing.

**Kortere geldigheid.** Let's Encrypt [verkort certificaten van 90 naar 45 dagen](https://letsencrypt.org/2025/12/02/from-90-to-45): sinds 13 mei 2026 voor het optionele tlsserver-profiel, en op 16 februari 2028 voor het standaardprofiel, waarbij ook het hergebruik van domeinvalidatie krimpt tot 7 uur. Vernieuw daarom automatisch op ongeveer tweederde van de geldigheid, of volgens ACME Renewal Information, en bewaak mislukte vernieuwingen. Een mislukte vernieuwing laat het certificaat verlopen, waardoor mailclients niet meer verbinden.

**Praktische punten.**

- Vervang het certificaat zonder herstart, zodat sessies en gegevens in het geheugen, zoals greylisting, behouden blijven.
- De sleutelbestanden van het account en het certificaat zijn serverbrede geheimen zoals de DKIM-sleutel: bestanden die alleen leesbaar zijn voor het serviceaccount, en geen versleutelingssleutel. Bij een migratie vraagt de nieuwe server eigen certificaten aan, zodra de hostnaam naar de nieuwe server wijst.
- Poorten onder 1024 (25, 80, 443, 465, 587 en 993) vragen een inrichtingskeuze buiten het pakket, zie hieronder. Dat geldt voor alle mailpoorten en staat los van TLS.

**Poorten onder 1024 en rootrechten.** Een niet-geprivilegieerd serviceaccount mag onder Linux zulke poorten niet zonder meer binden. Als root draaien lost dat op, maar is onnodig riskant: een fout in een parser of afhankelijkheid geeft een aanvaller dan de hele machine, en niet alleen wat het serviceaccount mag. Andere mailpakketten, zoals Postfix en Dovecot, binden de poorten als root en laten het verkeer daarna door onderprivilegieerde processen verwerken. Een JVM kan zichzelf volgens mijn kennis niet standaard omzetten, dus die route valt voor dit pakket af. Het ontwerp kiest voor het verlagen van de hostinstelling \`net.ipv4.ip\_unprivileged\_port\_start\`, bijvoorbeeld naar 25 en vastgelegd in \`/etc/sysctl.d\`. Dat werkt met en zonder Docker, ook als het pakket met \`--network host\` draait om het bronadres van de afzender te behouden, en is acceptabel op een dedicated mailserver, omdat het voor elke lokale gebruiker geldt. Het is hostconfiguratie en geen onderdeel van het pakket of van de data: bij een migratie moet de nieuwe host dezelfde instelling krijgen. In host-modus is er geen netwerkisolatie meer, dus houd de firewall strak. Alternatieven, in volgorde van voorkeur:

1. De capability `CAP_NET_BIND_SERVICE`, in systemd met `AmbientCapabilities`. Het proces draait als gewone gebruiker en mag alleen lage poorten binden.
2. Docker of Podman in de gewone netwerkmodus, waar de daemon de poorten publiceert. Controleer dat het echte IP-adres van de afzender bij de applicatie aankomt, anders gaan SPF-controles, greylisting en de begrenzing van aanmeldpogingen per IP-adres mis. Draait het pakket met \`--network host\`, dan geldt de instelling van de host en volstaat de capability \`NET\_BIND\_SERVICE\` alleen niet voor een gewone gebruiker in de container.
3. Poortdoorverwijzing met iptables (of nftables), zodat de applicatie op hoge poorten luistert. Een regel in de NAT-tabel stuurt verkeer voor bijvoorbeeld poort 25 door naar poort 2525, met een REDIRECT of DNAT. Dat is OS-configuratie op de host, net als de sysctl-instelling hierboven, en moet bij een migratie op de nieuwe host worden herhaald. Bij een REDIRECT of DNAT blijft het bronadres van de afzender behouden, zolang er geen SNAT of masquerade op het verkeer wordt toegepast. Controleer dat in de spike, vooral bij IPv6, waarvoor aparte regels nodig zijn (ip6tables of nftables). Regels moeten bovendien persistent worden gemaakt, anders verdwijnen ze bij een herstart. Een tussenschakel in de vorm van een proxy, in plaats van een doorverwijzing, laat de applicatie het adres van de proxy zien, tenzij die het echte adres doorgeeft.
4. Als root draaien, alleen als laatste redmiddel.

## 6. Mogelijkheden en onmogelijkheden

### 6.1 Wat dit ontwerp wél biedt

- Alle opgeslagen gegevens, inclusief headers en index, zijn onleesbaar zonder toegang tot de sleutels. Een gestolen schijf, een gelekte back-up of een kopie van de opslag levert een aanvaller dus niets bruikbaars op.
- Back-ups zijn van nature versleuteld en kunnen veilig bij derden worden bewaard.
- Een beheerder kan het systeem onderhouden zonder de mail te kunnen lezen (zolang er niemand is ingelogd en de beheerder de software niet aanpast).
- Volledige server-side zoekfunctionaliteit en compatibiliteit met standaard IMAP-clients, wat bij end-to-end-oplossingen vaak ontbreekt.
- Wachtwoordwijzigingen zijn goedkoop: alleen de ingepakte privésleutel hoeft te worden bijgewerkt, niet de mail.

### 6.2 Wat niet kan, of alleen met beperkingen

**Aanvallers met live-toegang.** Zodra de gebruiker is ingelogd, staat de sleutel in het geheugen. Op een gehuurde VPS kan de hypervisor het werkgeheugen lezen en snapshots maken. Wie een VPS huurt, loopt altijd het risico dat de hoster kan meekijken met alles wat er draait. Daar beschermt dit ontwerp niet tegen.

**Eigen hardware verkleint het risico, maar lost het niet op.** Op eigen hardware is toegang tot het geheugen aanzienlijk moeilijker dan op een gehuurde VPS, maar niet onmogelijk: een op afstand gecompromitteerde server geeft toegang tot het geheugen, en fysieke aanvallen (cold boot, DMA, een aangepaste bootloader) bestaan ook. Eigen hardware verkleint het aanvalsoppervlak flink, en een uitgeschakelde machine is veilig voor zover het wachtwoord sterk genoeg is.

**Het wachtwoord passeert de server.** Omdat de server de KEK uit het wachtwoord afleidt, moet het wachtwoord in leesbare vorm (over TLS) bij de server aankomen, bijvoorbeeld via IMAP LOGIN of AUTH PLAIN. Mechanismen als SCRAM voorkomen juist dat de server het wachtwoord ziet, maar maken dit ontwerp onmogelijk. Het ontwerp is daarom **zero-access at rest**: de server heeft in rust geen toegang, maar tijdens een sessie wel. Een aanvaller die de serversoftware aanpast, kan wachtwoorden onderscheppen.

**Offline wachtwoord raden.** Wie de schijf heeft, heeft ook de met het wachtwoord beschermde privésleutel en kan onbeperkt pogingen doen. De veiligheid van het hele systeem is dan gelijk aan de entropie van het wachtwoord en de kosten van Argon2id. Gebruik zware parameters, dwing lange wachtwoorden af of laat de gebruiker een willekeurig gegenereerde wachtzin gebruiken. Een lang, willekeurig app-wachtwoord levert veel meer bescherming dan een door een mens verzonnen wachtwoord.

**Het initiële wachtwoord en sleutelrotatie.** De beheerder heeft geen toegang meer zodra de gebruiker voor het eerst zijn wachtwoord wijzigt, mits die wijziging ook het sleutelpaar vervangt. Een gewone wachtwoordwijziging pakt alleen de bestaande privésleutel opnieuw in. Heeft de beheerder het beginwachtwoord gekend en een kopie van de oude, ingepakte privésleutel (bijvoorbeeld in een back-up), dan kan hij de privésleutel nog steeds ontsleutelen en alle toekomstige mail lezen. Daarom kent het ontwerp een **enrollment**-stap: bij de eerste login genereert het systeem een nieuw sleutelpaar, pakt alle bestaande berichtsleutels en de indexsleutel opnieuw in (goedkoop, de berichten zelf blijven staan) en vernietigt het oude paar. Back-ups van vóór dat moment blijven kwetsbaar voor wie het beginwachtwoord kende. Houd het beginwachtwoord daarom kort geldig en laat weinig mail bezorgen vóór de eerste login.

**Geen herstel mogelijk.** Dit is een bewuste eigenschap, maar ook een groot gebruiksrisico. Mitigaties zijn een herstelcode op papier of een extra slot met een tweede wachtwoord, bewaard door een vertrouwd persoon.

**Zoeken zonder ingelogd te zijn.** Niet mogelijk. Zoekbare versleuteling (searchable symmetric encryption) bestaat in de literatuur, maar lekt zoekpatronen en is complex. Dit ontwerp kiest bewust voor ontsleutelen op de server tijdens de sessie.

**Sleutels in het geheugen van een Java-proces.** Java geeft weinig controle: de garbage collector kopieert objecten, strings zijn niet te wissen en er is geen mlock. Beperk dit door sleutels in byte-arrays of off-heap geheugen (het Foreign Function and Memory API) te houden en deze expliciet te wissen, swap uit te zetten of te versleutelen, core dumps te blokkeren en het proces onder een eigen, minimaal geprivilegieerde gebruiker te draaien.

**Groter aanvalsoppervlak en onderhoudslast.** Een eigen SMTP-, IMAP- en DKIM-implementatie vervangt jarenlang beproefde software. Java beschermt tegen geheugenfouten zoals buffer overflows, maar niet tegen logische fouten, parserbugs, headerinjectie of fouten in protocoltoestanden. Een mailserver is bovendien direct bereikbaar vanaf het internet en krijgt continu ongevraagd verkeer. Ook de afleverbaarheid hangt af van strikte RFC-naleving, een goede IP-reputatie, reverse DNS en correcte SPF-, DKIM- en DMARC-records. Plan daarom fuzzing, snelle updates van afhankelijkheden en een externe review in.

**Accountbeheer door een beheerder is zelf een aanvalsroute.** Wie in de webinterface een account kan verwijderen en onder dezelfde naam opnieuw kan aanmaken, kan daarna alle nieuwe mail voor dat adres lezen, ook al blijft de oude mail onleesbaar. Daarvoor is geen toegang tot geheugen of schijf nodig, alleen een beheerdersaccount. Maatregelen: een verplichte wachttijd en een melding naar een door de gebruiker opgegeven tweede adres bij elke reset of herregistratie, een zichtbare wijziging van de IMAP-UIDVALIDITY en van de sleutelvingerafdruk die de gebruiker kan controleren, en een auditlog dat de beheerder niet ongemerkt kan wissen. Volledig uit te sluiten is het niet: wie accounts beheert, bepaalt wie een adres bezit.

**Rollen binnen het pakket scheiden.** Eén pakket betekent niet één proces met alle rechten. De internetgerichte SMTP-ontvangst heeft alleen publieke sleutels nodig en houdt dus nooit privésleutels vast. IMAP, submission en de webinterface bewaren sleutels alleen per sessie. Draai deze rollen als aparte processen onder aparte gebruikers, zodat een fout in de SMTP-parser niet leidt tot toegang tot de sleutels van ingelogde gebruikers.

### 6.3 Metadata en logs

Ook als alle inhoud versleuteld is, blijft er metadata over:

- **Logs van het pakket zelf** kunnen standaard minimaal worden ingericht: foutcodes en tellers, zonder adressen of onderwerpen. Gedetailleerde debuglogs zijn tijdelijk en worden niet bewaard. Bij losse software zoals Postfix bevatten de logs afzender, ontvanger, tijdstip en bericht-ID.
- **Enveloppegegevens** van binnenkomende mail zijn bij ontvangst bekend. Sla ze versleuteld op, en niet in een leesbare database.
- **Greylisting- en spamdatabases** bevatten wie met wie mailt. Bewaar ze alleen in het geheugen, met een korte bewaartermijn.
- **Groottes, tijdstippen en aantallen** van bestanden lekken activiteitsinformatie. Overweeg padding of vaste blokgroottes, met de kosten die daarbij horen.
- **Mapnamen, flags en UID-waarden** horen bij de versleutelde gegevens, niet bij onversleutelde bestandsnamen of metadata.
- **Uitgaande mail**: de wachtrij moet voor verzending leesbaar zijn voor de server (zie paragraaf 5.6). De wachtrij wordt niet versleuteld; het beschermen van uitgaande mail is geen doel van dit project. Kopieën in Verzonden gaan versleuteld naar de gebruiker.

## 7. Alternatieven en vergelijking

**A. Volledig eigen Java-server (het voorgestelde ontwerp).** Eén pakket met SMTP, IMAP, DKIM, spamfiltering, greylisting en webinterface, gebouwd op de protocol- en mailboxmodules van Apache James (paragraaf 5.9). Maximale controle, geen leesbare tussenopslag tussen componenten en een geïntegreerd versleutelde index, maar de bouwinspanning is zeer groot en een nieuwe implementatie draagt eigen beveiligingsrisico’s.

**B. Postfix en Dovecot met een per-gebruiker versleuteld volume.** Een eigen bezorgcomponent versleutelt binnenkomende mail met de publieke sleutel naar een spool. Bij inloggen wordt het per-gebruiker volume (bijvoorbeeld gocryptfs of fscrypt) ontsloten, de spool verwerkt en Dovecot gebruikt het volume als normale opslag, inclusief indexen en de full-text-plugin. Dit hergebruikt volwassen software en komt dicht bij hetzelfde beveiligingsniveau. Nadeel: zodra het volume is ontsloten, staat alles in leesbare vorm op dat volume, en de hele Dovecot-keten (met alle plugins) draait met toegang tot leesbare data. Dit is waarschijnlijk de snelste route naar een werkend prototype van het beveiligingsmodel, maar het is geen onderdeel van de eindoplossing: het hangt af van functies van het besturingssysteem en maakt migratie naar een andere server lastiger.

**C. Dovecot mail-crypt of Stalwart met aanvullende maatregelen.** Eenvoudigst, maar de index blijft het zwakke punt.

**D. End-to-end-benadering met client-side index.** Zoals bij sommige commerciële providers en lokale clients: de server heeft nooit de sleutel. Sterker tegen een actieve aanvaller, maar de client moet de zoekindex bijhouden, en standaard IMAP-clients werken niet of nauwelijks.

Variant B kan hooguit dienen als tijdelijke proefopstelling om het model te toetsen. De eindoplossing is variant A: onafhankelijk van functies van het besturingssysteem en eenvoudig naar een andere server te migreren.

## 8. Voorgestelde aanpak

1. **Dreigingsmodel vastleggen en toetsen** met de lijst uit paragraaf 4, en nagaan of deze groep aanvallers de moeite van het ontwerp rechtvaardigt.
2. **Spike met de James-modules**: laat de IMAP-modules draaien tegen een eigen mailbox-backend buiten de serverapplicatie en stel vast hoeveel van de mailbox-API headers en metadata in leesbare vorm teruggeeft. Dit beslist of de keuze uit paragraaf 5.9 houdbaar is.
3. **Proof of concept** van de inbound-keten: SMTP-ontvangst met versleutelde bezorging vóór de 250-bevestiging en ontsleuteling bij login, eventueel eerst als wegwerpproef met Postfix en Dovecot (variant B), die niet in de eindoplossing terechtkomt, om de aanpak en de afwezigheid van leesbare tussenopslag te valideren.
4. **Prototype van de versleutelde Lucene-Directory** los van mail: blokversleuteling, willekeurige leestoegang, prestaties zonder mmap en een benchmark met een representatieve mailbox.
5. **Sleutelbeheer**: enrollment, sleutelslots, herstelcode, rotatie, en een testplan voor de scenario’s verloren wachtwoord en ingetrokken app-wachtwoord.
6. **Protocollagen**: SMTP (ontvangst en submission), IMAP, DKIM, SPF en DMARC, greylisting en spamfiltering, op de protocol- en mailboxmodules van Apache James met een eigen versleutelde mailbox-backend (paragraaf 5.9), met interoperabiliteitstests tegen de clients en mailservers die je zelf gebruikt.
7. **Webinterface** voor accountbeheer en self-service wachtwoord- en sleutelbeheer, met gescheiden rollen voor beheerder en gebruiker.
8. **Onafhankelijke review** van het geheel, zeker van het cryptografische protocol, de protocollagen en het geheugenbeheer, voordat er echte mail op komt.

## 9. Open vragen

- Wat kost een versleutelde Directory aan prestaties voor typische mailzoekopdrachten en voor het opbouwen van een index van enkele gigabytes mail? Verwachting: de [documentatie van de Solr-encryptiemodule](https://apache.googlesource.com/solr-sandbox/+/55aa6fa8c90e0c550c2485dba787245b6c94adba/ENCRYPTION.md) noemt voor versleuteling van een Lucene-index op Java-niveau gemiddeld ongeveer 20% prestatieverlies bij de meeste zoekopdrachten en ongeveer 60% bij zoekopdrachten met meerdere termen. Dat komt uit een algemene benchmark en niet uit een mailbox. Een benchmark met een representatieve mailbox moet uitwijzen wat dit in de praktijk betekent.
- Hoe minimaal kan het bezorgjournaal worden gehouden, zodat er zo weinig mogelijk wordt gelekt over mappen en flags?
- Welke Argon2id-parameters (geheugen, iteraties, parallelisme) zijn in Bouncy Castle haalbaar op de beoogde VPS, en welke bibliotheek is voor de hybride post-quantum-sleutelinpakking het best onderhouden?
- Welke aanvullende inhoudsonafhankelijke controles zijn nodig om met greylisting en authenticatiecontroles een acceptabel spamniveau te halen?
- Wordt de indexstructuur op schijf zelf gebouwd, of is een bestaande embedded opslagbibliotheek geschikt, gegeven de eisen van afgesloten, onveranderlijke bestanden en eigen versleuteling?
- Schrijft Tika bij extractie uit een stream tijdelijke bestanden, en kan dat volledig naar tmpfs of het geheugen worden geleid, ook bij gebruik van de ForkParser?
- Welke Java ACME-bibliotheek is geschikt en onderhouden voor het aanvragen en verlengen van certificaten?

## 10. Conclusie

Het idee is technisch haalbaar en lost een echt gat op: de zoekindex is in bestaande stacks het zwakste punt van versleuteling at rest. Het combineren van hybride versleuteling bij binnenkomst, ontsleuteling bij login en een versleutelde per-gebruiker Lucene-index levert een systeem waarin niets van de mailbox leesbaar is zonder toegang tot de sleutels, ook de index niet, terwijl standaard IMAP en volledig zoeken behouden blijven.

Het ontwerp is zero-access at rest en beschermt niet tegen een aanvaller met live-toegang of een aangepaste server. De veiligheid hangt sterk af van de kwaliteit van het wachtwoord. Een wachtwoordwijziging gaat bij de eerste login gepaard met sleutelrotatie, zodat de beheerder echt buiten wordt gesloten, en eigen hardware verkleint het aanvalsoppervlak maar maakt geheugenaanvallen niet onmogelijk. Wie dat accepteert, krijgt een mailserver die voor een duidelijk omschreven dreigingsmodel een merkbare verbetering is ten opzichte van wat er nu beschikbaar is.

## 11. Referenties

- Bruno Roustant, [LUCENE-9379: Encrypting Directory](https://github.com/apache/lucene-solr/pull/1608), pull request apache/lucene-solr#1608 (2020). Proof of concept van een versleutelende Lucene-`Directory` met AES-CTR en een willekeurige IV per bestand; nooit samengevoegd. Bijbehorende discussie en benchmarks in [issue #10419](https://github.com/apache/lucene/issues/10419) (oorspronkelijk LUCENE-9379).
- Apache Solr sandbox, [documentatie van de Solr-encryptiemodule](https://apache.googlesource.com/solr-sandbox/+/55aa6fa8c90e0c550c2485dba787245b6c94adba/ENCRYPTION.md). Bron van de prestatiecijfers in paragraaf 5.4 en 9.
