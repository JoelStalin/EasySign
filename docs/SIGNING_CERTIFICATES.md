# Firma XML-DSig y certificados

`SigningEngine.signEcfXml` firma con **XML-DSig real** (enveloped, C14N 1.0, RSA-SHA256, digest SHA-256) usando una clave privada y un certificado X.509 reales. Antes de este cambio la "firma" era un hash simulado con un certificado inventado.

## Configuración
| Variable | Uso |
|---|---|
| `EASYSIGN_P12_PATH` | Ruta del archivo `.p12`/`.pfx` emitido por un prestador autorizado. |
| `EASYSIGN_P12_PASSPHRASE` | Clave del `.p12`. Nunca se registra en logs ni en mensajes de error. |

No guarde el `.p12` ni su clave en Git (política G6). Entréguelos por el mecanismo de secretos del despliegue.

## Reglas de entorno
- `environment: "production"`: exige certificado real y vigente. Sin certificado, o con el de pruebas, la firma se rechaza con `CERTIFICATE_REQUIRED`.
- `environment: "test"` (predeterminado) sin certificado configurado: usa un certificado autofirmado efímero cuyo titular dice `EasySign TEST - NOT VALID FOR PRODUCTION`. El resultado trae `testCertificate: true` y **no tiene valor legal**.
- Certificado vencido o aún no vigente: `CERTIFICATE_EXPIRED` / `CERTIFICATE_NOT_YET_VALID`.

## Verificación
`verifyEcfXml(signedXml, certificadoEsperadoPem?)` comprueba la firma contra el certificado incrustado en `KeyInfo`, o contra el esperado si se entrega. Cualquier modificación del documento invalida la firma.

## Pendiente (no afirmar cumplimiento DGII)
- Contrastar con la especificación oficial de la DGII: ubicación de la firma, `Reference URI`, transformaciones y la regla exacta del código de seguridad (hoy: primeros 6 caracteres de `SignatureValue`).
- Validar contra el XSD oficial y los vectores de prueba (ES-015). Hasta que pasen no se declara cumplimiento.
- Cadena de confianza, OCSP/CRL y HSM (ES-011). La firma de PDF sigue siendo simulada.
