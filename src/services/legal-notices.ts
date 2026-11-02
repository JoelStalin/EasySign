import { createHash } from "node:crypto";

/**
 * Mandatory disclosures of a non-qualified Proveedor de Servicios de Firma Electrónica
 * (Res. INDOTEL 067-2025, Annex II arts. 29.1-29.3 and 33 a-b). Plain Spanish.
 */

/** Art. 29.1-29.2: must appear in every communication about the service. */
export const NON_QUALIFIED_NOTICE =
  "Los certificados y servicios de firma de este proveedor no tienen el valor jurídico que la Ley 126-02 otorga a la firma digital ni a la firma digital segura. " +
  "Este proveedor no es una Entidad de Certificación autorizada por el INDOTEL.";

/** Art. 33 a: differences the subscriber must be told, in clear language. */
export const SIGNATURE_KINDS_EXPLANATION = [
  "Firma electrónica: datos en forma electrónica asociados a un documento para identificar a quien firma. Su valor probatorio puede discutirse y no equivale a la firma manuscrita por sí sola.",
  "Firma digital: se crea con un certificado emitido por una Entidad de Certificación y una clave privada bajo control del firmante.",
  "Firma digital segura: firma digital creada con un dispositivo seguro y un certificado de una Entidad de Certificación autorizada por el INDOTEL; tiene el valor legal de la firma manuscrita.",
].join("\n");

/** Art. 33 b: what must be told before the subscriber contracts. Every field is mandatory. */
export interface ServiceDisclosureConfig {
  providerName: string;
  /** Brand of the platform when it differs from the company name (e.g. "EasySign" operated by "GetUpSoft SRL"). Optional. */
  platformName?: string;
  rnc: string;
  /** Domicilio en la República Dominicana. */
  address: string;
  serviceDescription: string;
  certificateFeatures: string;
  liabilityLimitations: string;
  prices: string;
  serviceLevels: string;
  subscriberObligations: string;
  /** Canal para aclaraciones, fallas y reclamos. */
  claimsChannel: string;
}

export class DisclosureError extends Error {
  constructor(public readonly missing: string[]) {
    super(`Service disclosure is incomplete: missing ${missing.join(", ")}.`);
    this.name = "DisclosureError";
  }
}

export interface ServiceDisclosure {
  version: string;
  hash: string;
  nonQualifiedNotice: string;
  signatureKinds: string;
  config: ServiceDisclosureConfig;
  language: "es";
}

const REQUIRED: Array<keyof ServiceDisclosureConfig> = ["providerName", "rnc", "address", "serviceDescription", "certificateFeatures", "liabilityLimitations", "prices", "serviceLevels", "subscriberObligations", "claimsChannel"];
const FORBIDDEN_NAME = /entidad\s+de\s+certificaci[oó]n/i;

/** Builds the disclosure and refuses to publish an incomplete one or one that uses the reserved expression (art. 29.3). */
export function buildServiceDisclosure(config: Partial<ServiceDisclosureConfig>, version: string): ServiceDisclosure {
  const missing = REQUIRED.filter((k) => !String(config[k] ?? "").trim());
  if (missing.length) throw new DisclosureError(missing);
  const c = config as ServiceDisclosureConfig;
  if (c.platformName !== undefined && (!c.platformName.trim() || c.platformName.length > 80)) throw new DisclosureError(["platformName must be 1-80 characters when provided"]);
  if (FORBIDDEN_NAME.test(c.providerName) || FORBIDDEN_NAME.test(c.serviceDescription) || FORBIDDEN_NAME.test(c.platformName ?? "")) {
    throw new DisclosureError(["providerName/serviceDescription must not use 'Entidad de Certificación' (art. 29.3); the same applies to platformName"]);
  }
  const body = { version, nonQualifiedNotice: NON_QUALIFIED_NOTICE, signatureKinds: SIGNATURE_KINDS_EXPLANATION, config: c, language: "es" as const };
  return { ...body, hash: createHash("sha256").update(JSON.stringify(body)).digest("hex") };
}
