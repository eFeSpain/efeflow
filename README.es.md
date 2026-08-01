<div align="center">

<img src="assets/app.png" width="128" alt="eFeFlow">

# eFeFlow

**Diseñador visual de reglas de firewall nftables**

Diseña rulesets de nftables de Linux sobre un lienzo organizado por hook de
netfilter y prioridad de cadena. Importa lo que ya está en marcha, descubre qué
reglas no pueden coincidir nunca, y mira cómo un paquete recorre su camino real
por las cadenas.

[English](README.md) · [Español](README.es.md)

</div>

---

## Qué es

eFeFlow es un **diseñador**, no un gestor de firewall. Edita un ruleset y emite
código `nft`. Nada toca una máquina en producción salvo que se lo pidas
explícitamente.

### El lienzo es un campo, no una pizarra

En horizontal, cada cadena se sitúa en el hook de netfilter al que está
enganchada —`prerouting`, `input`, `forward`, `output`, `postrouting`— en el
orden en que un paquete los encuentra de verdad. En vertical, en su prioridad de
cadena: `raw` en −300, `dstnat` en −100, `filter` en 0, `srcnat` en +100.

**La posición es significado.** El orden de evaluación se lee en la pantalla en
lugar de reconstruirlo mentalmente. Las tarjetas se pueden arrastrar cuando otra
disposición encaja mejor con cómo piensas la red, y la organización automática
está a un botón de distancia.

Cada regla lleva una franja de color con su verdict, así que entornar los ojos
ante una cadena da el código de barras de la política.

### El analizador

Los hallazgos se derivan del ruleset en cada cambio, nunca están escritos a
mano. La relación central es la **subsunción**: la regla A subsume a la B cuando
todo paquete que casa con B casa también con A. Si A va antes y termina, B es
código muerto.

| Comprobación | Qué significa |
|---|---|
| **Eclipsada** | Una regla que ya decide otra anterior. Cuesta una evaluación y no cambia nada. |
| **Conflicto** | Reglas DNAT solapadas con destinos distintos. nftables termina en el primer veredicto NAT, así que una gana en silencio. |
| **Fusión** | Reglas que solo difieren en el puerto, sustituibles por una consulta a set: un sondeo hash en vez de *n* comparaciones. |
| **Sin usar** | Un set que se carga en el kernel en cada recarga y que ninguna regla consume. |
| **Fortificación** | Una cadena que da vía rápida a `established` pero nunca descarta `invalid`. |
| **Resiliencia** | Una regla de log sin límite de tasa, que inunda el ring buffer del kernel durante un escaneo. |

Las reglas con límite de tasa nunca se consideran eclipsantes. No son
deterministas, y señalarlas te haría borrar una regla que funciona.

Casi todos los hallazgos llevan una corrección de un clic que muta el modelo,
reemite el código y vuelve a analizar. Todo es deshacible.

### El simulador de paquetes

Evalúa contra el mismo modelo del que se emite el código, así que un veredicto
aquí es el veredicto que produce tu ruleset exportado. Llega ya ejecutado, y
cualquier cambio en el paquete lo relanza.

Modela la semántica de nftables, no una aproximación:

- **`accept` termina la cadena, no el paquete.** El paquete sigue hacia el hook
  siguiente. Solo `drop` y `reject` lo terminan del todo.
- **La dirección elige la ruta**, como hace la decisión de enrutado del kernel:
  entrada recorre prerouting e input; reenvío añade postrouting; salida empieza
  en output.
- **Desactivar el seguimiento de conexiones** marca el paquete como
  `untracked`, así que las reglas `ct state` ya no pueden casar con él y
  `ct status` nunca lo hace.
- **Los flags TCP** distinguen presencia de exclusividad: `tcp flags syn` casa
  con `syn|ack`; `tcp flags & (syn|ack) == syn` no.

El modo paso a paso avanza regla a regla con <kbd>Espacio</kbd>.

### Importar, y la verificación de ida y vuelta

Pega la salida de `nft list ruleset`, o léela de una máquina. Antes de importar
nada, eFeFlow lo analiza, **reemite cada regla desde el modelo** y compara ambas
línea a línea. El porcentaje que muestra es la única prueba honesta de que no se
ha perdido nada por el camino — y si una regla no se puede reproducir, te dice
cuál.

Las prioridades de cadena sobreviven por nombre (`priority filter` vuelve como
`priority filter`, no como `0`), y los contadores, los comentarios y los
sufijos `# handle` de `nft -a` se entienden todos.

### Exportar

Cuatro formatos, cada uno con salida realmente distinta: fichero de ruleset
atómico, delta incremental con comandos `add rule` para una máquina en marcha,
paquete de systemd con hook de validación previa, y playbook de Ansible con tus
sets extraídos como variables.

---

## La realidad de cada plataforma

`nft` solo existe en Linux, así que las integraciones nativas difieren:

| | Linux | Windows | macOS |
|---|:---:|:---:|:---:|
| Diseñar, analizar, simular, importar, exportar | ✅ | ✅ | ✅ |
| Validar con `nft -c` local | ✅ | — | — |
| Leer `nft list ruleset` local | ✅ | — | — |
| Todo lo anterior **por SSH** | ✅ | ✅ | ✅ |

SSH no es el plan B, es el diseño: el firewall rara vez es la máquina donde
tienes el editor abierto. eFeFlow delega en el `ssh` del sistema, así que tus
claves, tu agente y tu `~/.ssh/config` funcionan tal cual. Un destino Linux
local es simplemente el caso en que el host remoto es `localhost`.

Aplicar un ruleset valida primero y se niega sin confirmación explícita. Es la
única operación que puede dejarte fuera de una máquina.

---

## Ponerlo en marcha

```bash
npm install
npm run app          # aplicación de escritorio, con la capa nativa
npm run dev          # o solo el frontend en un navegador
npm test             # 54 aserciones
```

Compilar requiere los [prerrequisitos de Tauri](https://tauri.app/start/prerequisites/)
de tu plataforma. En Debian/Ubuntu:

```bash
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev patchelf
```

```bash
npm run app:build    # instaladores en src-tauri/target/release/bundle/
```

Etiquetar `v*` dispara el workflow de publicación, que compila en cuatro
runners —Linux, Windows, macOS arm64 y x86_64— y reúne los instaladores en un
borrador de release.

---

## Estructura

```
src/core/        puro, sin DOM, cubierto por npm test
  model.js         el ruleset y el vocabulario compartido
  parse.js         código nft → modelo
  generate.js      modelo → código nft, con procedencia de cada línea
  analyse.js       hallazgos, por subsunción de criterios
  simulate.js      evaluación de paquetes
  diff.js          diff LCS contra la última importación o exportación
src/app.js       la interfaz
src/native.js    puente con Rust; degrada a equivalentes de navegador
src-tauri/       transportes nft y ssh, comandos de ventana
```

La separación es lo importante: todo lo que decide un veredicto vive en `core/`
y se prueba sin navegador.

---

## Pruebas

Tres capas, porque una suite de núcleo en verde no demuestra que el producto
funcione — el simulador llegó a publicarse roto con todas las pruebas de núcleo
pasando, muerto por un parámetro que tapaba un helper.

**Núcleo** — el parser contra un volcado real de `nft list ruleset`, importar →
generar → importar como punto fijo sobre tres tablas, subsunción de criterios, y
evaluación de paquetes con conntrack, máscaras de flags y terminalidad de
cadena.

**Interfaz** — arranca la aplicación real en jsdom, recorre todas las pantallas
y dispara eventos reales. Seleccionar reglas, editar campos, deshacer, aplicar
correcciones, cambiar de idioma, ejecutar el simulador hasta el veredicto.

**Contratos** — guardas estáticas para los bugs que se colaron: todo id que
busca el código debe existir en el marcado; ningún parámetro puede llamarse como
un helper compartido; todo comando de ventana que invoca el frontend debe tener
su capacidad de Tauri; el trazado no puede derivar la altura de una tarjeta del
número de reglas.

```bash
npm test                            # todo
node --test "test/ui-*.test.js"     # solo la interfaz
```

---

## Licencia

MIT
