# Guía práctica (8 niveles)

Ejercicios **offline y locales** sobre framing de requests HTTP/1. No se
ejecuta Pingora ni se abre ningún socket. Cada respuesta está comprobada en
`tests/test_model.c` (`practice_level_N`), compilado con ASan/UBSan. Si
querés probar con software real, hacelo solo en un lab propio (VMs o
contenedores tuyos en una red aislada, con proxy y backend que controles),
nunca contra sistemas de terceros.

Comandos: `sh scripts/build.sh test`; después de `sh scripts/build.sh
results /tmp/r`: `./build/pgframe case 10|11 '<te>' '<cl>' <conn>` (listas
con `|`, `-` = sin cabecera).

**Básico**

1. **El caso normal.** HTTP/1.1 con `Content-Length: 5`. (`practice_level_1`:
   `AGREE`)
2. **HTTP/1.0 sin longitud.** ¿Dónde termina el body antes y después?
   (`practice_level_2`: `pre` `UNTIL_CLOSE`, `post` `LEN` 0)
3. **HTTP/1.0 con TE.** `Transfer-Encoding: chunked` en HTTP/1.0.
   (`practice_level_3`: `pre` `CHUNKED`, `post` `REJECT`)

**Intermedio**

4. **Dos líneas de TE.** `chunked` y después `identity`. ¿Cuál mira cada
   versión? (`practice_level_4`: `pre` `DESYNC`, `post` `REJECT`)
5. **Lista en una línea.** `gzip, chunked`. (`practice_level_5`: `pre`
   `LEN` 0, `post` `CHUNKED`)
6. **TE y CL juntos.** ¿Queda la conexión reutilizable? (`practice_level_6`:
   `pre` keepalive 1, `post` keepalive 0)

**Avanzado**

7. **El signo.** `Content-Length: +5` en `post`. ¿Qué dice la RFC y qué
   hace `str::parse::<i64>()`? (`practice_level_7`: `DESYNC`; observación,
   no hallazgo)
8. **Más estricto que la RFC.** `chunked,` (coma final) en `post`.
   (`practice_level_8`: `STRICTER`)

Más allá: agregá un caso a `fixtures/cases.tsv` con su etiqueta a mano,
regenerá `fixtures/expected.tsv` y comprobá que el modelo coincide. En tu
propio proxy: ¿de qué línea sale el framing, quién lo valida y qué pasa con
la conexión cuando hay dos cabeceras que se contradicen?
