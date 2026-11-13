# Cifrado en reposo de los documentos

Los documentos que se suben para firmar (`EASYSIGN_DOCS_DIR`) se guardan cifrados. Este documento explica cómo funciona, cómo se configura, cómo se rota la clave y qué queda fuera.

> Esto es una medida técnica de seguridad. No es un dictamen sobre la Ley 172-13 ni sobre ninguna otra norma; la política de datos personales la valida el abogado (ver "Lo que no cubre").

## Cómo funciona

Cifrado de sobre, solo con `node:crypto` (sin dependencias nuevas):

1. Cada documento recibe una clave de datos propia (DEK) de 32 bytes aleatorios y se cifra con **AES-256-GCM**.
2. La DEK se cifra ("se envuelve") con la clave maestra (KEK), también con AES-256-GCM. La KEK llega por variable de entorno y nunca se escribe en disco.
3. El archivo sigue llamándose como la **huella SHA-256 del documento en claro**. Al leer se descifra y se vuelve a calcular la huella; si no coincide, el documento no se entrega.
4. La huella forma parte de los datos autenticados de las dos capas, así que un archivo cifrado copiado bajo el nombre de otro documento no abre.

Rotar la KEK solo vuelve a envolver la DEK en la cabecera; el cuerpo cifrado no se reescribe.

### Formato del archivo (versión 1)

| Campo | Bytes | Contenido |
|---|---|---|
| magic | 6 | `ESDOC` seguido de un byte `0x00` |
| versión | 1 | `0x01` |
| longitud del id | 1 | longitud del id de la KEK |
| kekId | 1 a 64 | id de la KEK que envuelve la DEK (ASCII) |
| wrapIv | 12 | nonce del envoltorio de la DEK |
| wrapTag | 16 | etiqueta GCM del envoltorio |
| wrappedDek | 32 | DEK cifrada con la KEK |
| iv | 12 | nonce del contenido |
| tag | 16 | etiqueta GCM del contenido |
| ciphertext | resto | documento cifrado |

Datos autenticados: el envoltorio de la DEK autentica `magic + versión + longitud + kekId + huella`; el contenido autentica `magic + versión + huella`. El byte nulo del magic impide confundir un archivo antiguo sin cifrar con uno cifrado, porque ningún tipo aceptado (PDF, PNG, JPEG, texto UTF-8) puede empezar así.

Código: `src/services/document-crypto.ts` (formato y claves) y `src/services/document-store.ts` (almacén). Pruebas: `src/document-encryption.test.ts`.

## Configuración

| Variable | Contenido |
|---|---|
| `EASYSIGN_DOCS_KEK` | KEK actual: 32 bytes en base64 estándar (44 caracteres). |
| `EASYSIGN_DOCS_KEK_ID` | Id de la KEK actual. De 1 a 64 caracteres: letras, dígitos, punto, guion y guion bajo. Obligatorio si hay KEK. Ejemplo: `2026-11`. |
| `EASYSIGN_DOCS_KEK_PREVIOUS` | Opcional. KEK anteriores que todavía pueden descifrar, como `id:base64` separadas por comas: `2026-05:<base64>,2025-11:<base64>`. |

Para generar una KEK: `openssl rand -base64 32`. Guárdela en el gestor de secretos del despliegue (secretos de GitHub Actions o del servidor); **nunca en el repositorio ni en un `.env` versionado**. Los mensajes de error de configuración no incluyen material de clave.

Comportamiento según el entorno:

- **Producción (`NODE_ENV=production`) sin KEK:** el servicio no arranca y el error indica qué variables faltan.
- **Desarrollo sin KEK:** el servicio funciona y guarda los documentos sin cifrar; si hay `EASYSIGN_DOCS_DIR` escribe un aviso al arrancar. Sin `EASYSIGN_DOCS_DIR` los documentos viven solo en memoria y no hay nada en reposo.
- **Configuración mal formada** (clave que no mide 32 bytes, id inválido o repetido, `PREVIOUS` sin KEK actual): el servicio no arranca en ningún entorno.

**Si se pierde la KEK, los documentos cifrados con ella no se pueden recuperar.** Hay que tener copia de la KEK (y de las anteriores mientras queden archivos bajo ellas) fuera del servidor.

## Archivos anteriores sin cifrar

Los documentos escritos antes de activar el cifrado siguen siendo legibles: el almacén reconoce por la cabecera si un archivo está cifrado y, si no lo está, lo valida contra su huella igual que antes. No hace falta detener el servicio para activar la KEK. Para cifrarlos, ejecute el recifrado (siguiente sección).

## Recifrado y rotación de la KEK

```bash
npm run build
EASYSIGN_DOCS_DIR=... EASYSIGN_DOCS_KEK=... EASYSIGN_DOCS_KEK_ID=... npm run docs:reencrypt
```

El comando (`src/cli/reencrypt-documents.ts`, función `DocumentStore.reencryptAll()`):

- cifra los archivos que estaban en claro;
- vuelve a envolver con la KEK actual la DEK de los archivos que estaban bajo una KEK anterior;
- deja como están los que ya usan la KEK actual;
- antes de tocar un archivo comprueba que descifra y coincide con su huella, y lo reemplaza de forma atómica (archivo temporal y renombrado);
- si un archivo falla (clave que falta, archivo alterado) lo deja intacto y lo lista en `failed`.

Imprime un informe JSON (`encrypted`, `rewrapped`, `unchanged`, `failed`). Código de salida: `0` sin fallos, `1` si algún archivo falló, `2` si la configuración es inválida. Se puede repetir y ejecutar con el servicio en marcha.

Pasos para rotar:

1. Genere la KEK nueva y un id nuevo.
2. Despliegue con `EASYSIGN_DOCS_KEK` y `EASYSIGN_DOCS_KEK_ID` nuevos y añada la anterior a `EASYSIGN_DOCS_KEK_PREVIOUS` (`idAnterior:claveAnterior`). Desde ese momento los documentos nuevos usan la KEK nueva y los viejos siguen abriendo.
3. Ejecute `npm run docs:reencrypt` con esas mismas variables y confirme que `failed` está vacío.
4. Ejecútelo otra vez: debe informar `rewrapped: 0` y `encrypted: 0`.
5. Solo entonces quite la KEK anterior de `EASYSIGN_DOCS_KEK_PREVIOUS`. Conserve una copia mientras existan respaldos cifrados con ella.

Si la sospecha es que la KEK se filtró junto con los archivos, rotar no basta: quien tenga la KEK vieja y una copia vieja de los archivos puede abrirlos. Es un incidente de seguridad y se trata como tal.

## Errores

| Situación | Resultado |
|---|---|
| Archivo cifrado alterado, truncado o movido bajo otra huella | `DECRYPT_FAILED` |
| KEK con el mismo id pero distinta clave | `DECRYPT_FAILED` |
| Id de KEK no configurado, o archivo cifrado y servicio sin KEK | `KEY_UNAVAILABLE` |
| Archivo sin cifrar que no coincide con su huella | `NOT_FOUND` (igual que antes) |

En la API, `DECRYPT_FAILED` y `KEY_UNAVAILABLE` responden `500 DOCUMENT_UNAVAILABLE` con un mensaje genérico; el detalle (id de clave, causa) queda en el registro del servidor.

## Lo que no cubre

- **Los libros JSONL todavía no se cifran.** `EASYSIGN_REGISTRY_FILE`, `EASYSIGN_CONSENT_FILE`, `EASYSIGN_AUDIT_FILE` y `EASYSIGN_WORKFLOW_FILE` guardan datos personales (nombres, correos, teléfonos, IP, agente de usuario) en claro. Hasta que se cifren o pasen a PostgreSQL, hay que protegerlos con permisos de archivo y cifrado de disco.
- **Política de datos personales (Ley 172-13): pendiente del abogado.** Faltan plazos de retención, borrado, derechos de los titulares y tratamiento de los datos en libros inmutables. Este cifrado no resuelve nada de eso.
- **La KEK vive en una variable de entorno**, no en un HSM ni en un servicio de gestión de claves. Quien pueda leer el entorno del proceso puede descifrar.
- **Documentos en memoria:** sin `EASYSIGN_DOCS_DIR` no se cifran porque no llegan al disco. El proceso siempre tiene el documento en claro mientras lo sirve.
- **Respaldos:** los archivos cifrados se respaldan cifrados, pero el respaldo de la KEK es responsabilidad de la operación.
- **Nombres de archivo:** la huella SHA-256 del documento sigue visible como nombre. Quien ya tenga un documento puede comprobar si está almacenado.
- **Sin revisión criptográfica externa.** El diseño usa primitivas estándar, pero no lo ha auditado un tercero.

## Revertir

`git revert` del commit de la función. Los archivos ya cifrados dejarían de ser legibles con el código anterior: antes de revertir en un entorno con datos habría que descifrarlos, y hoy no existe un comando para eso.
