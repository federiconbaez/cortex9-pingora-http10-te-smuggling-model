# cortex9-pingora-http10-te-smuggling-model

Modelo offline de **CVE-2026-2835** (GHSA-hj7x-879w-vrp7, RUSTSEC-2026-0034,
CWE-444): antes de 0.8.0, el servidor HTTP/1 de Pingora leía un request
HTTP/1.0 sin `Content-Length` hasta el cierre de la conexión, aceptaba
`Transfer-Encoding` en HTTP/1.0 y decidía "chunked" mirando solo el
*primer* valor de `Transfer-Encoding` con coincidencia exacta. Un proxy y un
backend podían así discrepar sobre dónde termina un request. El GHSA nombra
tres commits de fix, los tres en 0.8.0 y ninguno en 0.7.0: 7f7166d, 40c3c1e
y 87e2e2f.
Educativo, determinista, C11 con ASan/UBSan. **No se compila ni ejecuta
Pingora, no se abre ningún socket.**

## Qué se modela

`pre` = 9ac75d0 (padre de 7f7166d) y `post` = 87e2e2f, con las líneas de
`server.rs` y `common.rs` citadas en el README en inglés: CL eliminado si
hay TE, keepalive apagado con TE+CL, HTTP/1.0+TE rechazado, TE final no
chunked rechazado, CL inválido rechazado, y sin TE ni CL longitud 0 (antes:
HTTP/1.0 hasta el cierre). Cada resultado se compara con `rfc`, una lectura
independiente de RFC 9112 §6.1 y §6.3 (no es código de Pingora).

## Evidencia diferencial

Sobre 576 cabeceras (`results/sweep.csv`): `pre` da 483 `DESYNC`, 42
`KEEPALIVE` y 177 lecturas hasta el cierre; `post` da 12 `DESYNC`, 0
`KEEPALIVE` y 0 lecturas hasta el cierre. Los 12 restantes son
`Content-Length: +5` o `-0`: `str::parse::<i64>()` de Rust acepta signo
(comprobado con rustc 1.99.1 local) y la RFC pide `1*DIGIT`. Es una
**observación del modelo**, no un hallazgo.

## Uso

```sh
sh scripts/build.sh test
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
./build/pgframe case 10 chunked - -
```

Fuentes: [SOURCES.md](SOURCES.md). Límites: [LIMITATIONS.md](LIMITATIONS.md).
Ejercicios: [PRACTICE.md](PRACTICE.md). Licencia: Apache-2.0.
