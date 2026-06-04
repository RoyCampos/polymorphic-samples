# Polymorphic Malware Sample Collection

> **Autor:** [0xp3rc](https://github.com/0xp3rc)

Colección curada de muestras de malware Win32 que exhiben **técnicas polimórficas y metamórficas** para pruebas autorizadas de validación de soluciones de detección y respuesta en endpoints (EDR/XDR) en entornos controlados y aislados.

## ⚠️ Disclaimer

> **ADVERTENCIA: Este repositorio contiene MALWARE REAL Y ACTIVO.**
>
> Este material es proporcionado **exclusivamente** con fines educativos, de investigación en seguridad y para pruebas autorizadas de soluciones EDR/XDR en entornos controlados.
>
> **Condiciones de uso:**
> - Solo debe utilizarse en entornos **virtualizados, sandboxed o air-gapped** con la debida autorización por escrito.
> - El usuario asume **total responsabilidad** por el uso de estas muestras.
> - Queda **estrictamente prohibido** utilizar estas muestras con fines maliciosos, en sistemas de producción, o sin la autorización explícita del propietario del entorno.
> - El manejo inadecuado puede resultar en **compromiso del sistema, pérdida de datos o consecuencias legales**.
>
> **El autor y los contribuidores no se hacen responsables** por daños directos, indirectos o consecuentes derivados del uso incorrecto, no autorizado o negligente de este material. Al descargar o utilizar este repositorio, usted acepta estos términos y confirma que cuenta con la autorización necesaria.

---

## Inventario de Muestras

### Tabla de Referencia Rápida

| # | Familia | Tipo | Password ZIP | Tamaño | Técnica Polimórfica |
|---|---------|------|:------------:|-------:|---------------------|
| 1 | Win32.Sality | Virus/Polimórfico | `infected` | 29 KB | Mutación de código, cifrado variable |
| 2 | Win32.Vobfus | Virus/Polimórfico | `infected` | 285 KB | Mutación de cuerpo en cada infección |
| 3 | Win32.Emotet | Trojan/Loader | `infected` | 62 KB | Repacking polimórfico server-side |
| 4 | Win32.Cutwail | Spam Botnet | `infected` | 170 KB | Packer polimórfico custom, anti-debug |
| 5 | Win32.Cridex | Banking Trojan | `infected` | 82 KB | Rotación de packers, cifrado de strings |
| 6 | Win32.Carberp | Banking Trojan | `infected` | 144 KB | Engine metamórfico, API hashing |
| 7 | Win32.ZeusVM | Banking Trojan | `infected` | 417 KB | Polimorfismo esteganográfico en imágenes |
| 8 | Win32.AgentTesla | Infostealer (.NET) | `infected` | 326 KB | Crypter polimórfico .NET, builds únicos |
| 9 | Dyre | Banking Trojan | `infected` | 2.2 MB | Mutación de packer, C2 cifrado |
| 10 | SpyEye | Banking Trojan | **`malware`** | 1.0 MB | Builder con engine de mutación |
| 11 | W32.Klez.H | Worm/Mass Mailer | `infected` | 288 KB | Cuerpo cifrado, decryptor stub variable |
| 12 | Net-Worm.Win32.Kido | Network Worm | `infected` | 60 KB | Packer polimórfico, DGA |
| 13 | Nivdort | Trojan/Downloader | `infected` | 491 KB | Cifrado multi-capa polimórfico |
| 14 | ZeroAccess | Rootkit/Trojan | `infected` | 166 KB | Mutación de PE, ocultamiento kernel |
| 15 | Rombertik | Trojan/Anti-Analysis | `infected` | 619 KB | Junk code masivo, anti-sandbox |
| 16 | Ransomware.Thanos | Ransomware (.NET) | `infected` | 145 KB | Builder genera builds polimórficos |
| 17 | Win32.Sofacy.A | APT Backdoor | `infected` | 59 KB | Ofuscación custom, payloads cifrados |
| 18 | Win32.Turla | APT Implant | `infected` | 423 KB | Code morphing, comms cifradas |
| 19 | Win32.Turla.V1 | APT Implant | `infected` | 97 KB | Variante con técnicas de evasión |

> **⚠️ NOTA:** Todas las muestras usan password `infected` excepto **SpyEye** que usa `malware`.

---

## Detalle Técnico por Familia

### 🔴 Polimorfismo Clásico (Mutación de Código)

#### Win32.Sality
- **Tipo:** Virus polimórfico / File infector
- **Era:** 2003 – presente (aún activo)
- **Password:** `infected`
- **SHA256:** `dd844482ea91586bf55c547d22649845c07e80916ea3554c024e7861416217b0`
- **MD5:** `a3088cf1da75891293bf1c94995169dd`
- **Técnica polimórfica:** Entry-Point Obscuring (EPO) con engine metamórfico. Genera un decryptor stub completamente diferente en cada infección. El cuerpo del virus está cifrado y el stub de descifrado muta estructuralmente usando sustitución de instrucciones, reordenamiento de bloques, e inserción de instrucciones basura. Adicionalmente opera una botnet P2P para actualizarse.
- **Qué detecta el XDR:** Modificación de ejecutables, inyección de procesos, comunicación P2P anómala, desactivación de antivirus.
- **MITRE ATT&CK:** T1091 (Replication Through Removable Media), T1080 (Taint Shared Content), T1562 (Impair Defenses)

#### Win32.Vobfus (Changeup)
- **Tipo:** Worm polimórfico
- **Era:** 2009 – presente
- **Password:** `infected`
- **SHA256:** `033570bf95d42dad2652ed0662a2369d954d4580d1b872ea44041697d0edc237`
- **MD5:** `3f0a46b1febcd33e25da42f6b491a273`
- **Técnica polimórfica:** Mutación completa del cuerpo del virus en cada propagación. Cada copia que genera a través de USB o red es estructuralmente diferente, produciendo un hash único cada vez. Utiliza ofuscación de control de flujo y cifrado de strings variable.
- **Qué detecta el XDR:** Creación masiva de archivos en medios removibles, autorun.inf malicioso, conexiones de descarga, variación de hashes.
- **MITRE ATT&CK:** T1091 (Replication Through Removable Media), T1547 (Boot or Logon Autostart Execution)

#### W32.Klez.H
- **Tipo:** Worm polimórfico / Mass Mailer
- **Era:** 2002 (clásico histórico)
- **Password:** `infected`
- **SHA256:** `207b2f769a23fd32dcc1b248bb82c20ca71454d474ba070ee0aca04cff6ad108`
- **MD5:** `ccde73ed3c6cbc2124db399359ae6ff9`
- **Técnica polimórfica:** Motor polimórfico clásico con cuerpo cifrado y decryptor stub variable. Cada instancia genera un stub de descifrado con instrucciones diferentes, registros diferentes y orden de operaciones diferente. Fue uno de los worms más prolíficos de su época precisamente por su capacidad de evadir firmas.
- **Qué detecta el XDR:** Envío masivo de email, explotación de vulnerabilidades IE, propagación por red compartida.
- **MITRE ATT&CK:** T1204 (User Execution), T1071 (Application Layer Protocol)

---

### 🟠 Polimorfismo Server-Side / Packer Mutation

#### Win32.Emotet
- **Tipo:** Trojan / Loader / Dropper modular
- **Era:** 2014 – presente (una de las amenazas más activas globalmente)
- **Password:** `infected`
- **SHA256:** `5b5bc00b4763c0bc089f0c747147b0845332be961d9839e75a60ef5db2382bb6`
- **MD5:** `099ec2767271a59ae4fd2cfa9844c9bf`
- **Técnica polimórfica:** **Polimorfismo server-side.** El servidor C2 re-empaqueta el binario cada vez que un endpoint lo descarga, produciendo un hash SHA256 único por descarga. Utiliza macros en documentos Office con ofuscación variable, múltiples capas de packing, y payloads que mutan en cada entrega. Es considerado uno de los malware más polimórficos modernos.
- **Qué detecta el XDR:** Documentos Office con macros, descarga de payloads, movimiento lateral (EternalBlue), inyección de procesos, C2 sobre HTTPS.
- **MITRE ATT&CK:** T1059 (Command and Scripting Interpreter), T1547 (Boot or Logon Autostart Execution), T1055 (Process Injection)

#### Win32.AgentTesla
- **Tipo:** Infostealer / Keylogger (.NET)
- **Era:** 2014 – presente (Top 5 malware global)
- **Password:** `infected`
- **SHA256:** `71a0d6adc569d1a1d50e8e865a05c10887d849ed3b18a78096af917a19a716e4`
- **MD5:** `7ce44be24584e94d69bbf4cbdc8c1115`
- **Técnica polimórfica:** Utiliza **crypters polimórficos .NET** que envuelven el payload en capas de ofuscación que cambian con cada build. Los operadores usan builders que generan binarios con hash único, strings cifradas con claves diferentes, y control de flujo ofuscado. Cada campaña produce muestras que evaden firmas previas.
- **Qué detecta el XDR:** Keylogging, captura de pantalla, robo de credenciales de browsers/email/FTP, exfiltración por SMTP/FTP/Telegram.
- **MITRE ATT&CK:** T1056 (Input Capture), T1041 (Exfiltration Over C2 Channel), T1555 (Credentials from Password Stores)

#### Dyre (Dyreza)
- **Tipo:** Banking Trojan
- **Era:** 2014 – 2016
- **Password:** `infected`
- **SHA256:** `a6f10947d6c37b62a4c0f5e4d0d32cc826a957c7d1026f316d5651262c4f0b24`
- **MD5:** `6d1f649d90313b7e3624c0e86563b5dd`
- **Técnica polimórfica:** Emplea **mutación de packer** donde cada distribución usa un packer diferente o configuración diferente del mismo packer, generando binarios estructuralmente distintos. Utiliza man-in-the-browser para interceptar sesiones bancarias y cifrado personalizado para comunicación C2.
- **Qué detecta el XDR:** Inyección en browsers, hooking de APIs, comunicación C2 cifrada, exfiltración de credenciales bancarias.
- **MITRE ATT&CK:** T1185 (Browser Session Hijacking), T1071 (Application Layer Protocol), T1055 (Process Injection)

#### SpyEye
- **Tipo:** Banking Trojan
- **Era:** 2009 – 2013
- **Password:** **`malware`** ⚠️
- **SHA256:** `fa3b854f0e4c0d35ca9a5647bc6935ee1e6a3920d9b951c51b2cb7bc1588c904`
- **MD5:** `2e0bb844572de2e88cbd23d76101bd16`
- **Técnica polimórfica:** Incluye un **builder con engine de mutación** que permite a los operadores generar binarios únicos con cada build. El builder modifica la estructura del PE, cifra strings con claves diferentes, y reorganiza el código. Sucesor directo de ZeuS, competía por infectar las mismas máquinas.
- **Qué detecta el XDR:** Form grabbing, web injection, keylogging, kill de antivirus, rootkit en user-mode.
- **MITRE ATT&CK:** T1185 (Browser Session Hijacking), T1055 (Process Injection), T1014 (Rootkit)

#### Net-Worm.Win32.Kido (Conficker)
- **Tipo:** Network Worm polimórfico
- **Era:** 2008 – 2009 (infectó ~15 millones de máquinas)
- **Password:** `infected`
- **SHA256:** `d3d7bf970f8fc019cf06e276e20f5b3b9411f9b39cc43048d76bf292db3a820f`
- **MD5:** `15054c1e49e004b8011dbef3bfa97d08`
- **Técnica polimórfica:** **Packer polimórfico** que genera una estructura PE diferente en cada propagación. Complementa con **Domain Generation Algorithm (DGA)** que genera 50,000 dominios diarios para C2, haciendo imposible bloquear todas las posibles comunicaciones. Explotaba MS08-067.
- **Qué detecta el XDR:** Escaneo de red SMB, explotación de vulnerabilidades Windows, DGA, modificación de servicios del sistema, desactivación de Windows Update.
- **MITRE ATT&CK:** T1210 (Exploitation of Remote Services), T1568 (Dynamic Resolution/DGA), T1562 (Impair Defenses)

---

### 🟡 Metamorfismo / Anti-Análisis

#### Win32.Carberp
- **Tipo:** Banking Trojan con engine metamórfico
- **Era:** 2010 – 2013
- **Password:** `infected`
- **SHA256:** `353b02ed1c66cd06a4c0c2bb7cf2e07abbe73b2cdcc9f02336768c5aeed9a1c3`
- **MD5:** `dd34fed8a105ad224a98f7f0058afb49`
- **Técnica polimórfica:** Posee un **engine metamórfico** que transforma el código a nivel de instrucción, sustituyendo secuencias de instrucciones por equivalentes funcionales pero diferentes en bytes. Utiliza API hashing dinámico para ocultar las llamadas a la API de Windows y bootkit para persistencia pre-OS.
- **Qué detecta el XDR:** Web injection, robo de credenciales, modificación de MBR/bootkit, inyección de procesos.
- **MITRE ATT&CK:** T1055 (Process Injection), T1185 (Browser Session Hijacking), T1542 (Pre-OS Boot)

#### Win32.Cridex (Bugat/Feodo)
- **Tipo:** Banking Trojan polimórfico
- **Era:** 2012 – 2014
- **Password:** `infected`
- **SHA256:** `6dc2dfc92e1ba3c3ddcf02d08cbe99054ee99ad1c2395f940ac8f398f3a468cc`
- **MD5:** `d1a667d57ef9bcd460a3871d639240ce`
- **Técnica polimórfica:** Emplea **rotación de packers** — alterna entre diferentes packers comerciales y custom para generar variantes con estructura PE diferente. Complementa con cifrado de strings donde cada build usa claves de cifrado diferentes para las cadenas de texto.
- **Qué detecta el XDR:** Inyección en procesos del browser, form grabbing, comunicación C2 por HTTP, persistencia en registro.
- **MITRE ATT&CK:** T1055 (Process Injection), T1071 (Application Layer Protocol), T1547 (Boot or Logon Autostart Execution)

#### Win32.Cutwail
- **Tipo:** Spam Botnet polimórfico
- **Era:** 2007 – presente
- **Password:** `infected`
- **SHA256:** `64c68894407ec425ba179815d44b567b02a72056d8e79d9223062e0a60ea3b3a`
- **MD5:** `db2cc70364a13c3e10789a53043371f3`
- **Técnica polimórfica:** Utiliza un **packer polimórfico custom** con capacidades anti-debugging y anti-VM. Cada variante del bot se genera con ofuscación diferente y técnicas de evasión de sandbox actualizadas. Genera automáticamente nuevas variantes para distribución masiva por email.
- **Qué detecta el XDR:** Envío masivo de spam, proxy de tráfico, comunicación C2 cifrada, anti-debugging.
- **MITRE ATT&CK:** T1071 (Application Layer Protocol), T1090 (Proxy), T1497 (Virtualization/Sandbox Evasion)

#### Rombertik
- **Tipo:** Trojan con polimorfismo anti-análisis
- **Era:** 2015
- **Password:** `infected`
- **SHA256:** `c1aed0999337544d19ea857dc40743ec8b484c2d8ec6997207e5672539110b22`
- **MD5:** `e39bfb63f8febee08eb8eda80bda7151`
- **Técnica polimórfica:** Implementa **polimorfismo anti-análisis extremo** con inserción masiva de junk code (~97% del binario es código basura que nunca se ejecuta). Escribe 960 millones de bytes de datos aleatorios para agotar sandbox timeouts. Si detecta análisis, destruye el MBR como mecanismo anti-forense.
- **Qué detecta el XDR:** Captura de formularios web, destrucción de MBR si detecta análisis, evasión de sandbox, escritura masiva a disco.
- **MITRE ATT&CK:** T1497 (Virtualization/Sandbox Evasion), T1027 (Obfuscated Files), T1561 (Disk Wipe)

#### ZeroAccess (Sirefef)
- **Tipo:** Rootkit polimórfico / Trojan
- **Era:** 2011 – 2013 (botnet de ~9 millones de máquinas)
- **Password:** `infected`
- **SHA256:** `769f6ab4c26caa66c0d1c43f7b1ab28e51bdbec94e473da04e59517c741aaf8c`
- **MD5:** `25b0dfbf8d762ddf965d62760af11895`
- **Técnica polimórfica:** **Mutación de PE polimórfica** que modifica la estructura del ejecutable en cada infección. Usa rootkit en kernel-mode para ocultarse completamente del sistema operativo. Crea un volumen virtual oculto para almacenar sus componentes donde el antivirus no puede escanear.
- **Qué detecta el XDR:** Rootkit kernel-mode, click fraud, criptominería, P2P botnet, modificación de drivers del sistema.
- **MITRE ATT&CK:** T1014 (Rootkit), T1027 (Obfuscated Files), T1564 (Hide Artifacts)

#### Nivdort (Bayrob)
- **Tipo:** Trojan polimórfico / Downloader
- **Era:** 2014 – 2016
- **Password:** `infected`
- **SHA256:** `3fbdede25a0eb245357501033b64adcd9380e592f386ef05748ca3d9b42910af`
- **MD5:** `2cf9704b9ad48c05501f372a26d14636`
- **Técnica polimórfica:** Utiliza **cifrado multi-capa polimórfico** donde cada capa de cifrado usa algoritmos y claves diferentes. El binario está envuelto en múltiples capas de ofuscación que se desempaquetan secuencialmente en runtime. Incluye detección de VM y sandbox para evadir análisis automatizado.
- **Qué detecta el XDR:** Descarga de payloads adicionales, proxy de tráfico, robo de credenciales, evasión de sandbox multi-capa.
- **MITRE ATT&CK:** T1027 (Obfuscated Files), T1497 (Virtualization/Sandbox Evasion), T1105 (Ingress Tool Transfer)

---

### 🟣 Builder-Based Polymorphism

#### Ransomware.Thanos
- **Tipo:** Ransomware polimórfico (.NET)
- **Era:** 2020
- **Password:** `infected`
- **SHA256:** `cd0f55dd00111251cd580c7e7cc1d17448faf27e4ef39818d75ce330628c7787`
- **MD5:** `00184463f3b071369d60353c692be6f0`
- **Técnica polimórfica:** Primer ransomware con **builder que genera variantes polimórficas** automáticamente. Cada build produce un binario con hash único, strings cifradas con claves diferentes, y estructura de código reorganizada. Implementa la técnica **RIPlace** para evadir protecciones anti-ransomware basadas en monitoreo de rename operations.
- **Qué detecta el XDR:** Cifrado masivo de archivos, técnica RIPlace, exfiltración pre-cifrado, modificación de shadow copies, nota de rescate.
- **MITRE ATT&CK:** T1486 (Data Encrypted for Impact), T1027 (Obfuscated Files), T1490 (Inhibit System Recovery)

---

### 🔵 APT con Técnicas de Ofuscación/Mutación

#### Win32.Sofacy.A (APT28 / Fancy Bear)
- **Tipo:** APT Backdoor
- **Era:** 2014 (atribuido a grupo estatal)
- **Password:** `infected`
- **SHA256:** `1ca6fe4c75c16fed18e49e8e26dc8ef9aaa83ff9ad50e3a9ed335d10a18245a5`
- **MD5:** `93d9031291d074ad45ea3dd132410144`
- **Técnica polimórfica:** Emplea **ofuscación custom** con payloads cifrados que mutan entre campañas. Utiliza técnicas de string encryption, dead code insertion, y cifrado de comunicaciones C2 con claves rotativas. Los operadores generan variantes únicas por target.
- **Qué detecta el XDR:** Beacon C2, exfiltración de datos, credential harvesting, persistencia en registro, evasión de detección.
- **MITRE ATT&CK:** T1059 (Command and Scripting Interpreter), T1105 (Ingress Tool Transfer), T1041 (Exfiltration Over C2)

#### Win32.Turla (Snake/Uroburos)
- **Tipo:** APT Implant
- **Era:** 2008 – presente (atribuido a grupo estatal)
- **Password:** `infected`
- **SHA256:** `8d83cc02582a4549afa69341e5ad6a82533652d065cca5114b5cded5191a7ab2`
- **MD5:** `806f6d32670941011893896069bcedd8`
- **Técnica polimórfica:** Utiliza **code morphing** avanzado con comunicaciones cifradas a través de canales satelitales hijackeados. Cada deployment incluye un dropper único con ofuscación diferente. Implementa rootkit para persistencia invisible y usa named pipes para comunicación inter-proceso cifrada.
- **Qué detecta el XDR:** Rootkit, comunicación satelital anómala, persistencia avanzada, named pipe communication, kernel hooking.
- **MITRE ATT&CK:** T1014 (Rootkit), T1071 (Application Layer Protocol), T1573 (Encrypted Channel)

#### Win32.Turla.V1
- **Tipo:** APT Implant (variante)
- **Era:** 2008 – presente
- **Password:** `infected`
- **SHA256:** `4e596e44727a51165c60add5e43730791eb769f9f3cd9e7c265abec3293979e2`
- **MD5:** `3c2dfe47b8f5f80055a382309f3622d0`
- **Técnica polimórfica:** Variante del implant Turla con técnicas de evasión polimórficas actualizadas. Implementa diferentes métodos de inyección y persistencia respecto a la versión principal.
- **Qué detecta el XDR:** Similar a Win32.Turla con variaciones en las técnicas de persistencia.
- **MITRE ATT&CK:** T1014 (Rootkit), T1071 (Application Layer Protocol)

#### Win32.ZeusVM
- **Tipo:** Banking Trojan
- **Era:** 2014
- **Password:** `infected`
- **SHA256:** `7a981d743a601ca2ae40f78547430bcd404f93520b0ba78e2ca53edf8a0f31f0`
- **MD5:** `b73f3134bb5ee95d8deb3abdfc9b1263`
- **Técnica polimórfica:** Implementa **polimorfismo esteganográfico** — oculta su configuración dentro de imágenes JPG usando esteganografía. Cada variante codifica la configuración con claves diferentes dentro de imágenes diferentes, haciendo que la detección basada en la configuración sea imposible. Incluye detección de VMs para evadir sandboxes.
- **Qué detecta el XDR:** Descarga de imágenes con datos ocultos, web injection, man-in-the-browser, form grabbing, evasión de VM.
- **MITRE ATT&CK:** T1027 (Obfuscated Files), T1185 (Browser Session Hijacking), T1497 (Virtualization/Sandbox Evasion)

---

## Clasificación por Técnica Polimórfica

| Técnica | Descripción | Familias que la implementan |
|---------|-------------|----------------------------|
| **Metamorphic Engine** | El código se transforma estructuralmente entre infecciones — sustituye instrucciones por equivalentes | Sality, Carberp |
| **Polymorphic Decryptor** | Payload cifrado con stub de descifrado que muta (diferentes registros, instrucciones, orden) | Sality, Klez.H, Vobfus |
| **Server-Side Polymorphism** | El servidor C2/distribución genera un binario único por descarga | Emotet, AgentTesla |
| **Packer Rotation** | Cicla entre diferentes packers/crypters para variar la estructura del PE | Cridex, Cutwail, Dyre, Conficker |
| **Builder Polymorphism** | Builder/configurador genera builds únicos con código reorganizado | Thanos, SpyEye |
| **Domain Generation (DGA)** | Generación algorítmica de dominios C2 (polimorfismo de infraestructura) | Conficker/Kido |
| **Junk Code Insertion** | Inserción masiva de código basura para alterar hash y evadir análisis estático | Rombertik, ZeroAccess |
| **Steganographic Mutation** | Configuración oculta en imágenes con codificación variable | ZeusVM |
| **Multi-Layer Encryption** | Múltiples capas de cifrado con algoritmos y claves variables | Nivdort, Dyre |
| **Crypter Wrapping** | Crypter .NET/nativo produce hash único por build | AgentTesla, Nivdort |

---

## Estructura de Archivos

### Por Familia

Cada directorio de muestra contiene:

| Archivo | Descripción |
|---------|-------------|
| `*.zip` | Archivo protegido con password que contiene el binario de malware |
| `*.sha256` | Hash SHA-256 del archivo ZIP para verificación de integridad |
| `*.sha` / `*.shasum` | Hash SHA-1 del archivo ZIP (formato alternativo) |
| `*.md5` | Hash MD5 del archivo ZIP |
| `*.pass` | Password del archivo ZIP |

### Árbol del Repositorio

```
win/
├── Dyre/
│   ├── Dyre.zip                    (2.2 MB)
│   ├── Dyre.sha256
│   ├── Dyre.md5
│   └── Dyre.pass                   → infected
├── Net-Worm.Win32.Kido/
│   ├── Net-Worm.Win32.Kido.zip     (60 KB)
│   ├── Net-Worm.Win32.Kido.sha256
│   ├── Net-Worm.Win32.Kido.md5
│   └── Net-Worm.Win32.Kido.pass    → infected
├── Nivdort/
│   ├── Nivdort.zip                 (491 KB)
│   ├── Nivdort.sha256
│   ├── Nivdort.md5
│   └── Nivdort.pass                → infected
├── Ransomware.Thanos/
│   ├── Ransomware.Thanos.zip       (145 KB)
│   ├── Ransomware.Thanos.shasum
│   ├── Ransomware.Thanos.md5
│   └── Ransomware.Thanos.pass      → infected
├── Rombertik/
│   ├── Rombertik.zip               (619 KB)
│   ├── Rombertik.sha256
│   ├── Rombertik.md5
│   └── Rombertik.pass              → infected
├── SpyEye/
│   ├── SpyEye.zip                  (1.0 MB)
│   ├── SpyEye.sha256
│   ├── SpyEye.md5
│   └── SpyEye.pass                 → malware ⚠️
├── W32.Klez.H/
│   ├── W32.Klez.H.zip              (288 KB)
│   ├── W32.Klez.H.sha256
│   ├── W32.Klez.H.sha
│   ├── W32.Klez.H.md5
│   └── W32.Klez.H.pass             → infected
├── Win32.AgentTesla/
│   ├── Win32.AgentTesla.zip         (326 KB)
│   ├── Win32.AgentTesla.sha256
│   ├── Win32.AgentTesla.md5
│   └── Win32.AgentTesla.pass        → infected
├── Win32.Carberp/
│   ├── Win32.Carberp.zip            (144 KB)
│   ├── Win32.Carberp.sha256
│   ├── Win32.Carberp.md5
│   └── Win32.Carberp.pass           → infected
├── Win32.Cridex/
│   ├── Win32.Cridex.zip             (82 KB)
│   ├── Win32.Cridex.sha256
│   ├── Win32.Cridex.md5
│   └── Win32.Cridex.pass            → infected
├── Win32.Cutwail/
│   ├── Win32.Cutwail.zip            (170 KB)
│   ├── Win32.Cutwail.sha256
│   ├── Win32.Cutwail.md5
│   └── Win32.Cutwail.pass           → infected
├── Win32.Emotet/
│   ├── Win32.Emotet.zip             (62 KB)
│   ├── Win32.Emotet.sha256
│   ├── Win32.Emotet.md5
│   └── Win32.Emotet.pass            → infected
├── Win32.Sality/
│   ├── Win32.Sality.zip             (29 KB)
│   ├── Win32.Sality.sha256
│   ├── Win32.Sality.md5
│   └── Win32.Sality.pass            → infected
├── Win32.Sofacy.A/
│   ├── Win32.Sofacy.A.zip           (59 KB)
│   ├── Win32.Sofacy.A.sha256
│   ├── Win32.Sofacy.A.md5
│   └── Win32.Sofacy.A.pass          → infected
├── Win32.Turla/
│   ├── Win32.Turla.zip              (423 KB)
│   ├── Win32.Turla.sha256
│   ├── Win32.Turla.md5
│   └── Win32.Turla.pass             → infected
├── Win32.Turla.V1/
│   ├── Win32.Turla.v1.zip           (97 KB)
│   ├── Win32.Turla.v1.shasum
│   ├── Win32.Turla.v1.md5
│   └── Win32.Turla.v1.pass          → infected
├── Win32.Vobfus/
│   ├── Win32.Vobfus.zip             (285 KB)
│   ├── Win32.Vobfus.sha256
│   ├── Win32.Vobfus.md5
│   └── Win32.Vobfus.pass            → infected
├── Win32.ZeusVM/
│   ├── Win32.ZeusVM.zip             (417 KB)
│   ├── Win32.ZeusVM.sha256
│   ├── Win32.ZeusVM.md5
│   └── Win32.ZeusVM.pass            → infected
├── ZeroAccess/
│   ├── ZeroAccess.zip               (166 KB)
│   ├── ZeroAccess.sha256
│   ├── ZeroAccess.md5
│   └── ZeroAccess.pass              → infected
│
└── Invoke-SampleValidation.ps1      # Script de automatización
```

---

## Uso del Script de Validación

### 1. Solo validar integridad (sin extracción)

```powershell
.\Invoke-SampleValidation.ps1 -Mode Validate
```

### 2. Validar y extraer

```powershell
.\Invoke-SampleValidation.ps1 -Mode Extract -ExtractPath "C:\Lab\Samples"
```

> **Requiere [7-Zip](https://7-zip.org/)** para extracción de ZIPs protegidos con password.

### 3. Pipeline completo (Validar → Extraer → Ejecutar)

```powershell
.\Invoke-SampleValidation.ps1 -Mode Full -ExtractPath "C:\Lab\Samples"
```

- Solicita confirmación explícita (`CONFIRM`) antes de ejecutar
- Delay de 15 segundos entre muestras para observación de telemetría EDR/XDR
- Registra toda la actividad con timestamps en archivo de log

### Parámetros del Script

| Parámetro | Default | Descripción |
|-----------|---------|-------------|
| `-Mode` | `Validate` | `Validate` / `Extract` / `Execute` / `Full` |
| `-SamplesPath` | Directorio del script | Ruta a los directorios de muestras |
| `-ExtractPath` | `%TEMP%\PolyTestSamples` | Destino para binarios extraídos |
| `-LogPath` | Auto-generado | Ruta custom para el archivo de log |

---

## Verificación Manual de Integridad

En la máquina Windows destino:

```powershell
# SHA-256
Get-FileHash -Algorithm SHA256 .\Win32.Emotet.zip

# MD5
Get-FileHash -Algorithm MD5 .\Win32.Emotet.zip

# SHA-1 (para archivos .sha / .shasum)
Get-FileHash -Algorithm SHA1 .\W32.Klez.H.zip
```

---

## Requisitos del Entorno

- **OS:** Windows 10/11 (x64) — virtualizado
- **Red:** Aislada / air-gapped recomendado
- **Herramientas:** PowerShell 5.1+, 7-Zip (para extracción)
- **EDR/XDR:** Debe estar instalado y monitoreando activamente antes de la ejecución de muestras

## Safety Checklist

- [ ] El entorno está virtualizado (snapshot de VM tomado antes de las pruebas)
- [ ] La red está aislada o monitoreada con captura completa de paquetes
- [ ] El agente EDR/XDR está activo y reportando telemetría
- [ ] La documentación de autorización está archivada
- [ ] Todos los hashes de muestras fueron validados antes de la extracción
- [ ] Post-prueba: revertir snapshot de VM a estado limpio

---

## Licencia

Este repositorio se proporciona estrictamente para investigación de seguridad autorizada y pruebas defensivas. Todas las muestras provienen de repositorios públicos de malware. Sin garantías expresas ni implícitas.
