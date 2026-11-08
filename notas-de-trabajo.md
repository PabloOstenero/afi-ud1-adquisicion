# Notas de trabajo · Adquisición de FORENSIC_10

## 0. Datos del caso y entorno

| Dato | Valor |
|---|---|
| Máquina investigada | `FORENSIC_10` (VirtualBox), Windows 7 SP1 de 32 bits (`manage-bde` versión 6.1.7601), PowerShell 2.0 |
| Memoria de la VM | 1024 MB |
| USB de respuesta | Unidad `D:` dentro de la VM, etiqueta «Pen profesor», 3,56 GB. |
| Anfitrión | Sistema Operativo Windows 7 |

Observación: VirtualBox muestra el tipo de SO de la VM como «Windows Vista (64-bit)», mientras que el sistema invitado es Windows 7 de 32 bits.

## 1. Preparación

### 1.1 USB de respuesta
- Formato: NTFS
- Herramientas copiadas a `D:\USB-RESPUESTA\`: DumpIt, script respuesta-en-vivo.ps1, velociraptor
- Hashes SHA-256 de cada herramienta, calculados antes de empezar y guardados en `hashes-herramientas.txt`.
- El `.exe` de Velociraptor 0.77.3 legacy que venía con el material coincide con el hash del `LEEME`: `89034042c0b956ce071cc5c23c0409702a2a3a463c7fd935c888ff7f3f26fb4f`.
- Hash de `velociraptor-v0.76.1-windows-386-legacy.exe` (versión que finalmente funcionó): ecafdd1122ffc02d933337a87fd9fef1cff5af5a

## 2. Marca de autoría (2026-11-03 09:32)

1. Bloc de notas abierto, sin guardar, con el texto: `AFI-PabloOstenero-20261103`. Hora: [09:32]
2. Fichero `AFI-PabloOstenero-20261103.txt` creado en el escritorio con el mismo texto. Hora: [09:32]

Es la única escritura deliberada en el equipo investigado (excepción prevista en el enunciado).

## 3. Parte 1 · Adquisición en vivo

### 3.1 Estado inicial (2026-11-03 09:34)
- Captura de la pantalla inicial: ![Pantalla inicial](capturas/Marca.png)
- Hora del sistema (`Get-Date`): 09:34. Zona horaria: UTC+1.
- Hora real (referencia): 09:34. Desfase: 00:00.

### 3.2 Memoria RAM (2026-11-05 13:53 – 14:02)
- Herramienta: DumpIt, versión 1.3.2.20110401.
- Ejecutada desde el USB, como administrador, con salida al USB.
- Fichero: FORENSE-06-20261105-125305.raw, tamaño 0.99 GB.
- Hash SHA-256 (`certutil -hashfile <fichero> SHA256`; PowerShell 2.0 no tiene `Get-FileHash`): BBE1DDB8ECE31D8C4960F4A722433D496BAF42B64F2BE8B38C69B1D8FA935A97. Hora del cálculo: 16:10.

### 3.3 Datos volátiles (2026-11-06 16:39 - 16:49)
- Herramienta: `respuesta-en-vivo.ps1`, ejecutado desde el USB con PowerShell abierto como administrador.
- **Incidencias** (véase sección 7, nº 1 y 2): el script original falló en PowerShell 2.0. Se adaptó una versión compatible.
- Cambios de la versión adaptada: `$PSScriptRoot` sustituido por `$MyInvocation`; `Get-CimInstance` por `Get-WmiObject`; los cmdlets de red y usuarios por `netstat`, `net` y WMI; `Get-BitLockerVolume` por `manage-bde -status`; `Get-FileHash` por SHA-256 de .NET; fichero solo en ASCII.
- Salida: carpeta con `00-registro.txt` y `hashes-sha256.csv`. Hash del registro: 00f15cc923ab92aaeb3910203fae48eebadb7ff7f794f7c2fe31751697435d05. Hash del CSV: ec065f3a2e45990258cb27a8364ed0bb90a859acc704241b4f9a7406f5dab26b.

### 3.4 Tráfico de red (captura parcial)
Se captura desde fuera de la VM, sin instalar nada en ella, con VirtualBox en el anfitrión.

**Primer intento (17:02).** Se fijó la ruta y se activó la captura con:
```
VBoxManage controlvm "FORENSIC_10" nictracefile1 D:\salida\CASO-01\red.pcap
VBoxManage controlvm "FORENSIC_10" nictrace1 on
```
`VBoxManage showvminfo "FORENSIC_10" | findstr /i "NIC Trace"` mostró `Trace: off (file: D:\salida\CASO-01\red.pcap)` y `dir` confirmó que ni `D:\salida` ni `D:\salida\CASO-01` existían. VirtualBox guardó la ruta pero no creó la carpeta, y no se escribió ningún `.pcap`. **No existe captura del tramo anterior** (RAM, volátiles y triaje).

**Segundo intento.**
```
mkdir D:\salida\CASO-01
VBoxManage controlvm "FORENSIC_10" nictracefile1 D:\salida\CASO-01\red.pcap
VBoxManage controlvm "FORENSIC_10" nictrace1 on
```
- Hora de activación: 2026-11-07 16:59.
- Hora de desactivación (`nictrace1 off`): 17:05.
- Tamaño de `red.pcap`: 123KB. Hash (`certutil -hashfile D:\salida\CASO-01\red.pcap SHA256`): 33228a768a8cd23f59356bc1194430610a604e43c907d231206194218f02f43d.
- **La captura es parcial:** empieza después de la RAM, los volátiles y el triaje.

### 3.5 Triaje

**Herramienta y por qué.** El enunciado exige KAPE o un recolector offline de Velociraptor. Se probó KAPE primero y después Velociraptor; la versión que funciona en este Windows 7 de 32 bits es **Velociraptor 0.76.1 windows-386-legacy**. Todos los fallos están en la sección 7.

**Preparación.** Consola como administrador, en `D:\USB-RESPUESTA\windows\triaje\Velociraptor`. Para no escribir en `C:`, los temporales se redirigen al USB:
```
mkdir D:\USB-RESPUESTA\salida\tmp
set TEMP=D:\USB-RESPUESTA\salida\tmp
set TMP=D:\USB-RESPUESTA\salida\tmp
```

**Búsqueda del artefacto.** Se volcó la lista completa de artefactos al USB (`artifacts list > ...\lista-artefactos.txt`). `Windows.KapeFiles.Targets` y `Windows.Triage.Targets` no existen en esta compilación (`findstr /i "targets"` no devolvió nada). Sí existe `Generic.Collectors.File` (alias `Windows.Collectors.File`), que recoge ficheros por rutas (globs). Sus parámetros están en `show-collectors-file.txt`. Admite el parámetro `Accessor`, que se cambia a `ntfs` para leer `$MFT` y los ficheros bloqueados.

**Artefacto personalizado.** Se creó una copia de `Generic.Collectors.File` llamada `Custom.Triage.Windows7`, con dos cambios: tabla de rutas propia y `Accessor` por defecto en `ntfs`. Las rutas recogidas (relativas a `C:`):

```
$MFT
$LogFile
Windows\System32\config\SYSTEM
Windows\System32\config\SOFTWARE
Windows\System32\config\SAM
Windows\System32\config\SECURITY
Windows\System32\config\DEFAULT
Users\*\NTUSER.DAT
Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat
Windows\System32\winevt\Logs\*.evtx
Windows\Prefetch\*.pf
Windows\AppCompat\Programs\Amcache.hve
Windows\System32\Tasks\**
Windows\Tasks\*.job
Windows\System32\drivers\etc\hosts
Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk
Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*
ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*
```
No se recogen los ficheros del escritorio ni documentos del usuario, como pide el enunciado. `$UsnJrnl` no se incluyó porque no estaba claro que esta versión lo admitiera con `glob`.
- Hash de `triaje-win7.yaml`: 31aed454b35f63638aa316c2080cb6efc96763f5c1381df1aece0a024ec58afe

**Ejecución (2026-11-07 16:20 - 16:35).** Comando: velociraptor-v0.76.1-windows-386-legacy.exe --definitions D:\USB-RESPUESTA\windows\triaje\Velociraptor\definiciones artifacts collect Custom.Triage.Windows7 --output D:\USB-RESPUESTA\salida\triaje\triaje-velociraptor.zip > D:\USB-RESPUESTA\salida\triaje\velociraptor-consola.txt 2>&1

**Resultado.**
- Fichero: `D:\USB-RESPUESTA\salida\triaje\triaje-velociraptor.zip`, 27,9 MB.
- SHA-256: `d2b2ecd00c1785db5287ac8b90e7e997ce87adac7f51015ef24147a36e33eb56` 
- La consola solo contiene `"Error": null` (sin errores). No aparecen líneas `Found` ni `Skipping` en pantalla; esos mensajes van a los registros dentro del zip.
- `findstr /i /m "%24MFT"` y `findstr /i /m "NTUSER SOFTWARE"` sobre el zip devolvieron el nombre del fichero, lo que indica que esas cadenas aparecen dentro. **Es una pista, no una prueba**; la comprobación definitiva se hace en Linux (`unzip -lv`, sección 5).
- El zip no se descomprimió en la máquina investigada.

### 3.6 Comprobación del cifrado (2026-11-07 17:01)
Comando, en una consola como administrador:
```
manage-bde -status
```
Resultado (captura en `capturas/`):

| Volumen | Tamaño | Versión BitLocker | Estado de conversión | Protección | Protectores de clave |
|---|---|---|---|---|---|
| `C:` (OS Volume) | 31,90 GB | None | Fully Decrypted (0 %) | Off | None Found |
| `D:` (Data Volume, «Pen profesor») | 3,56 GB | None | Fully Decrypted (0 %) | Off | None Found |

**Conclusión:** BitLocker no está activo en ninguno de los volúmenes visibles. Sin protectores de clave no hay claves de recuperación que obtener ni volumen descifrado que adquirir en vivo, así que no se realiza ninguna acción adicional. La comprobación se ha limitado a BitLocker. [COMPLETAR si se hicieron otras comprobaciones, por ejemplo `wmic logicaldisk`.]

### 3.7 Apagado (2026-11-07 17:09)
**Decisión:** corte de energía inmediato, no apagado ordenado.

**Motivo.** Con la RAM, los volátiles, la red y el triaje ya adquiridos, y sin volúmenes cifrados, no queda ningún dato volátil por preservar. El apagado ordenado obliga a Windows a ejecutar su secuencia de cierre: escribe en disco, modifica el registro y los registros de eventos, actualiza ficheros temporales y de paginación, y ejecuta procesos y servicios que podrían alterar o borrar rastros. El corte de energía evita todo eso y deja el disco lo más cercano posible al estado que tenía durante la intervención.

**Inconvenientes asumidos.** NTFS puede quedar sin cerrar limpiamente y se pierden los datos en caché sin escribir. Se acepta porque lo volátil ya está adquirido y el disco se imagina tal cual está.

**Ejecución.** Antes de apagar se desactivó la captura de red y se calculó su hash. Método: menú de VirtualBox → Apagar la máquina. No se usó la señal ACPI ni «Guardar el estado», para no crear ficheros nuevos en la carpeta de la VM. La VM no se ha vuelto a arrancar.

## 4. Parte 2 · Adquisición post-mortem
 
Todo se realiza en el anfitrión, con la VM `FORENSIC_10` apagada y VirtualBox cerrado, en PowerShell como administrador. Numeración de evidencias: disco = 05, pendrive = 06.
 
### 4.1 Disco de la máquina
 
#### 4.1.1 Documentación de la máquina
Comandos:
```
$vbm = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
& $vbm snapshot "FORENSIC_10" list
& $vbm showvminfo "FORENSIC_10" | findstr /i "State Config Snapshot SAS"
& $vbm showvminfo "FORENSIC_10" | findstr /i "vdi"
```
Resultado (capturas en `capturas/`):
- Instantáneas: ninguna (`This machine does not have any snapshots`).
- Fichero de configuración: `D:\maquinas_virtuales\FORENSIC_10\FORENSIC_10.vbox`. Carpeta de instantáneas: `D:\maquinas_virtuales\FORENSIC_10\Snapshots`.
- Estado: apagada (`powered off`, desde 2026-11-07 16:09:16 según VirtualBox). 
- Almacenamiento: un controlador SAS (`LsiLogicSas`, 8 puertos) con un único disco: `D:\maquinas_virtuales\FORENSIC_10\FORENSIC_10_disk0.vdi`. Capacidad virtual: 32.768 MB.

#### 4.1.2 Hash «antes» de cada fichero de la carpeta (16:55:08 – 16:55:41)
```
$vm   = "D:\maquinas_virtuales\FORENSIC_10"
$dest = "D:\caso\disco"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
cd $vm
Get-ChildItem -Recurse -File | Get-FileHash -Algorithm SHA256 | Select-Object Hash, Path | Export-Csv "$dest\hashes-vm-antes.csv" -NoTypeInformation
```
Resultado: `hashes-vm-antes.csv`, con los 8 ficheros que contiene la carpeta (no hay `.nvram`, aunque `showvminfo` indica su ruta):
 
| Fichero | Tamaño (bytes) | SHA-256 |
|---|---|---|
| `FORENSIC_10.vbox` | 2.636 | 89AD3F19548438C6A232CF2F27F861C7FFFCB1FEC9D2678C18BF0906CB0B6EB0 |
| `FORENSIC_10.vbox-prev` | 3.331 | 4007CFA4FE4A0227B0FCA27EADD2F1C75D3CA99E8321470F9ECD9CDE05B5CF73 |
| `FORENSIC_10_disk0.vdi` | 13.372.489.728 | 75F2350B1B00F8ED356FB1253C19E88E2F6DF038C916C50A661C131B3AC1190F |
| `Logs\VBox.log` | 398.497 | C16114929377FB5144E3F4F3A5DE0B02E64F5371D29786ADB455233A4EF7A73A |
| `Logs\VBox.log.1` | 374.015 | 0ED60331B54417C45065A216C545EFD4FF09462FCE438B159D554B7B129BA840 |
| `Logs\VBox.log.2` | 373.367 | E657322A5A08B10805C403CCAD468BCF8277F47204EE00A09877E2DFFBD56448 |
| `Logs\VBox.log.3` | 377.469 | EC422D479CB927EF9108D6EC5AF8F79A44DAC64EDD4A0B1C7C7F3C5FAD0CB7DA |
| `Logs\VBoxHardening.log` | 516.878 | A9562339ED247E0A86254A7E674F3FC21A07589675C8981F75311F043CE35881 |
 
`FORENSIC_10.vbox-prev` es una copia anterior de la configuración que crea VirtualBox; se incluye en todos los hashes y comparaciones.
 
#### 4.1.3 Imagen del disco
 
**Primer intento (descartado), FTK Imager 3.1.1.8.** Se eligió `File → Create Disk Image → Image File → FORENSIC_10_disk0.vdi`, formato E01 con *Verify images*, destino `D:\caso\disco`, nombre `PC-ADMIN`. Se generaron `PC-ADMIN.E01` a `PC-ADMIN.E04` y `PC-ADMIN.E01.txt` (fragmentación por defecto, no se puso Fragment Size 0). La verificación dio Match en MD5 y SHA1, sin sectores defectuosos, pero:
- El número de sectores fue 26.118.144, que por 512 bytes son 13.372.489.728 bytes: exactamente el tamaño del fichero `.vdi`, no el del disco (32.768 MB).
- Al abrir la imagen en FTK Imager, el visor hexadecimal mostraba al principio el texto `<<< Oracle VirtualBox Disk Image >>>` y el árbol no mostraba particiones.
Conclusión: FTK Imager 3.1.1.8 no interpreta el formato `.vdi` y lo trató como un fichero cualquiera, de modo que esa imagen es una copia del contenedor y no del disco que contiene. **No se utiliza como imagen del disco.** Se conserva (con su `.txt` y su captura) en `D:\caso\disco\primer-intento\` como parte del historial.
 
**Solución: conversión a disco en bruto y nueva imagen.**
 
1. Conversión con VirtualBox, sin instalar nada en la máquina investigada:
```
   & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" clonemedium disk "D:\maquinas_virtuales\FORENSIC_10\FORENSIC_10_disk0.vdi" "D:\caso\disco\PC-ADMIN.raw" --format RAW
```
   Hora de inicio: 17:32. Fin: 17:33:09 (fecha de modificación del `.raw`). UUID del medio creado: `0e3b6434-f4e5-4064-b7ab-e5b30ff432fd`.
2. Comprobación de tamaño: `PC-ADMIN.raw` mide 34.359.738.368 bytes, igual que la capacidad del disco virtual (32.768 MB × 1.048.576), es decir, 67.108.864 sectores de 512 bytes.
3. SHA-256 de `PC-ADMIN.raw` (17:36:50 – 17:37:58): `9D9393E61C6178ED4A466293D692586BB2484B88FF1E15619525864E4E6B0BA2`.
4. Nueva imagen con FTK Imager: `File → Create Disk Image → Image File → PC-ADMIN.raw`, formato E01, *Verify images after they are created*, número de caso 001, número de evidencia 05, destino `D:\caso\disco`, nombre `PC-ADMIN-DISCO`, Fragment Size 0, compresión 6. Hora de inicio y fin: 17:44.
5. Verificación: 67.108.864 sectores, MD5 `6e8ffc4a88831d33425ca26427a339bb` y SHA1 `7b826ed7b51b58227bc6376bf56e0dbdfb329d28`, ambos Match, sin sectores defectuosos. La imagen es un único fichero.
6. SHA-256 de la imagen y de su informe (17:52:12 – 17:52:29), con `Get-FileHash D:\caso\disco\PC-ADMIN-DISCO.E0*`, guardados en `hashes-e01.csv`:
 
   | Fichero | SHA-256 |
   |---|---|
   | `PC-ADMIN-DISCO.E01` | 867D050D858BE25521F4FCEBF41591B2CE6E67077831DB82E10FE142E8437068 |
   | `PC-ADMIN-DISCO.E01.txt` | 8E27FE608F8A9583123CFE6A68BCEDF5FC1783BA1B4E8C5304C3F4A66672F7E6 |
 
**Por qué estas herramientas.** FTK Imager porque es la herramienta indicada para el anfitrión Windows y verifica la imagen al terminar. `clonemedium` porque VirtualBox ya está instalado y evita añadir software; convierte el `.vdi` en el disco que contiene. `dd` no sirve: copiaría el contenedor con su formato.
 
#### 4.1.4 Hash «después» y comparación (17:40:29 – 17:41:05)
```
cd $vm
Get-ChildItem -Recurse -File | Get-FileHash -Algorithm SHA256 | Select-Object Hash, Path | Export-Csv "$dest\hashes-vm-despues.csv" -NoTypeInformation
Compare-Object (Import-Csv "$dest\hashes-vm-antes.csv") (Import-Csv "$dest\hashes-vm-despues.csv") -Property Hash, Path
```
`Compare-Object` no devolvió ninguna diferencia: ningún fichero de la carpeta de la VM cambió, ni siquiera tras abrir el `.vdi` con `clonemedium`. Captura en `capturas/`.
 
#### 4.1.5 Copia de configuración y registros (17:58:16)
```
Copy-Item "$vm\*.vbox" D:\caso\disco\
Copy-Item "$vm\FORENSIC_10.vbox-prev" D:\caso\disco\
Copy-Item "$vm\Logs" D:\caso\disco\Logs -Recurse
```
A las 18:00:38 se comparó el SHA-256 de cada copia con la fila correspondiente de `hashes-vm-antes.csv` (script con `Where-Object` y `-eq` sobre el hash): los 7 ficheros (`.vbox`, `.vbox-prev`, `VBox.log`, `.1`, `.2`, `.3` y `VBoxHardening.log`) dieron `OK`. Captura en `capturas/`.
 
El hash del `.vdi` y el de la imagen no coinciden, y es lo esperado: uno es del fichero contenedor y el otro del contenido del disco. Cada uno se compara consigo mismo: el `.vdi`, antes y después; la imagen, con su verificación.
 
### 4.2 Pendrive encontrado
 
#### 4.2.1 Documentación
- Fotos por delante y por detrás: ![usb 1](capturas/usb%20delante.jpeg) ![usb 2](capturas/usb%20detras.jpeg)
- Marca y modelo: Verbatim STORE N GO. Capacidad: 57,8 GB. Número de serie: `90005C80F5824415`. Número de evidencia: 06..
- Contenido previo visible en la imagen: carpetas `linux`, `salida` y `windows`, y ficheros `hashes-herramien…` y `LEEME.txt` (fechas de octubre de 2026). Forma parte de la evidencia.

#### 4.2.2 Marca de autoría en el pendrive
La marca no estaba en el pendrive al empezar. Se creó antes de adquirirlo, con el bloqueo desactivado, con el mismo texto que la marca de la VM: `AFI-PabloOstenero-20261103`. Es una modificación deliberada del pendrive, anterior a la protección, y su fecha de creación es el 2026-11-08, no la del día de la marca original.
 
#### 4.2.3 Bloqueo de escritura (software, `bloqueo-usb.ps1`)
El script avisa de que es un bloqueo por software. Registro en `C:\Users\pablo\Documents\bloqueo-usb.log`
 
| Hora | Acción / resultado |
|---|---|
| 18:37:49 | Política global `WriteProtect=1` (primer intento, con otro USB). |
| 18:38:23 | Comprobación de `E:` y `F:`: no deja escribir → PROTEGIDO. |
| 19:01:18 | Comprobación de `G:` (Verbatim) con la política desactivada: ESCRIBE → NO PROTEGIDO. El botón *Solo lectura (disco seleccionado)* falló con `Set-DiskMode` no reconocido. |
| 19:04:58 | Política global `WriteProtect=1`; el pendrive se desconectó y se volvió a conectar. |
| 19:05:24 | Comprobación: `G:` → no deja escribir → **PROTEGIDO**. `E:` y `F:` (el USB de respuesta, que ya estaba conectado) → ESCRIBE → NO PROTEGIDO. |
 
Captura de la comprobación PROTEGIDO en `capturas/`.
 
#### 4.2.4 Imagen
FTK Imager (versión 3.1.1.8): `File → Create Disk Image → Physical Drive → Verbatim STORE N GO (57,8 GB)`, elegido por modelo y capacidad y no por el número de disco del bloqueador; disco físico completo. Formato E01, *Verify images*, evidencia 06, destino `D:\caso\pendrive`, nombre `PENDRIVE-ENCONTRADO`, Fragment Size 0, compresión 6. Hora de inicio y fin: 19:12 - 19:42
 
Resultado:
- 121.145.344 sectores (62.026.416.128 bytes, igual que los 57,8 GB del disco).
- MD5 `155d3c2a470eef3fb404bb1d4c09bc7e` y SHA1 `a6b39ff94f8007e12adc7409ad8cca7966e97a11`, ambos Match, sin sectores defectuosos.
- Imagen en un único fichero de 8.458.125.415 bytes (la compresión aprovecha el espacio vacío).
- SHA-256 (19:45:11 – 19:45:21), `Get-FileHash D:\caso\pendrive\PENDRIVE-ENCONTRADO.E0*`, en `hashes-pendrive.csv`:
  | Fichero | SHA-256 |
  |---|---|
  | `PENDRIVE-ENCONTRADO.E01` | 266ACA61B73AFB5314612E5BC6DF7FBA3A7C88066B65F5F6FB0F571992033759 |
  | `PENDRIVE-ENCONTRADO.E01.txt` | 1D32265642F77E0ACFA4DE6C09749346FAD840101576B87D9630EF6EADAA64D4 |

Comprobación de contenido: al abrir la E01 en FTK Imager se ve `Partition 1 [59152MB]` (NTFS, etiqueta `STORE N GO`) y `Unpartitioned Space`, es decir, el disco completo. En la raíz aparece la marca (`AFI-PabloOstener…`, fecha 08/11/2026) y su contenido es `AFI-PabloOstenero-20261103`. Captura en `capturas/`.
 
También aparece un fichero borrado `.prueba-bloqueo-…` (fecha 08/11/2026): lo creó y borró el botón *Comprobar* de `bloqueo-usb.ps1` a las 19:01:18, cuando el pendrive aún no estaba protegido. Es una escritura propia previa a la protección y la imagen la conserva.
 
#### 4.2.5 Cierre
Orden: cerrar FTK Imager, quitar el pendrive con *Quitar hardware de forma segura*, desactivar la política en `bloqueo-usb.ps1` (19:55) y copiar `bloqueo-usb.log` sin editarlo a `hashes/`.

## 7. Incidencias y errores

| Nº | Hora | Qué pasó | Causa | Qué hice |
|---|---|---|---|---|
| 1 | 16:12 | El script `respuesta-en-vivo.ps1` no arrancó: `You must provide a value expression on the right-hand side of the '-' operator` (línea 80, `-notin`). | PowerShell 2.0 no tiene los operadores `-in` y `-notin`. | Se sustituyó por `-notcontains`. |
| 2 | 16:18 | Segundo error: `Cannot bind argument to parameter 'Path' because it is null` en `Join-Path $PSScriptRoot 'salida'` (línea 22). | `$PSScriptRoot` no existe dentro de un script en PowerShell 2.0. | Se pasó `-Destino` explícito y se adaptó el script completo a PowerShell 2.0 (ver 3.3). |
| 3 | 16:24 | Los cmdlets modernos del script (`Get-CimInstance`, `Get-NetTCPConnection`, `Get-FileHash`...) no existen en PowerShell 2.0. | Versión antigua de PowerShell. | Sustituidos por WMI y comandos nativos. |
| 4 | 17:20 | KAPE se cerró con «ha dejado de funcionar». Detalle: `System.NotSupportedException` al negociar TLS. | El .NET Framework de este Windows 7 no soporta los protocolos TLS modernos. Persistió tras tocar ficheros de configuración y la clave del registro `SchUseStrongCrypto`. | Se descartó KAPE. |
| 5 | 18:30 | Velociraptor `amd64`: «no es una aplicación Win32 válida». | El sistema es de 32 bits. | Se descartó esa compilación. |
| 6 | 19:03 | Velociraptor 0.77.3 `386-legacy` no arrancó. | Faltan las bibliotecas Universal C Runtime (`api-ms-win-crt-*.dll`). Los intentos con paquetes `.msu` fallaron por restricciones del entorno. | [COMPLETAR: cómo se resolvió con la 0.76.1 legacy y qué se cambió en el equipo o en el USB]. |
| 7 | 12:41 | `artifacts show Windows.KapeFiles.Targets` y `Windows.Triage.Targets`: «not found». | Esta compilación no incluye esos artefactos. | Se usó `Generic.Collectors.File` con rutas propias (ver 3.5). |
| 8 | 17:02 | Captura de red: el primer intento no generó ningún `.pcap`. | La carpeta `D:\salida\CASO-01` no existía y VirtualBox no la crea. | Se creó la carpeta y se repitió; la captura es parcial (ver 3.4). |
| 9 | 17:20 | La primera E01 del disco (`PC-ADMIN.E01`–`.E04`) tenía 26.118.144 sectores y, en el visor hexadecimal, la cabecera `<<< Oracle VirtualBox Disk Image >>>`. | FTK Imager 3.1.1.8 trata el `.vdi` como un fichero y no lee el disco que contiene. | Se conservó como historial y se hizo una nueva imagen a partir de un `.raw` creado con `clonemedium` (4.1.3). |
| 10 | 19:01 | El botón *Solo lectura (disco seleccionado)* de `bloqueo-usb.ps1` devolvió `Set-DiskMode` no se reconoce como cmdlet. | El script llama a un cmdlet que no existe en este Windows. | Se usó *Activar para todos los USB* (política global). No se modificó el script. |
| 11 | 19:01:18 | La comprobación con el pendrive sin proteger escribió un fichero de prueba que luego se borró (`.prueba-bloqueo-…`). | El botón *Comprobar* prueba escribiendo. | Se documenta; el fichero borrado aparece en la imagen. Desde entonces, *Comprobar* solo con el pendrive protegido. |
