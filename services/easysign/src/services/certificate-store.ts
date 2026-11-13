import { readFileSync } from "node:fs";
import forge from "node-forge";

export interface LoadedCertificate {
  privateKeyPem: string;
  certificatePem: string;
  /** Hex serial number as issued by the CA. */
  serial: string;
  issuer: string;
  subject: string;
  notBefore: Date;
  notAfter: Date;
  /** True for the ephemeral self-signed certificate used only in the test environment. */
  isTest: boolean;
}

export class CertificateError extends Error {
  constructor(
    public readonly code: "CERTIFICATE_REQUIRED" | "CERTIFICATE_INVALID" | "CERTIFICATE_EXPIRED" | "CERTIFICATE_NOT_YET_VALID",
    message: string
  ) {
    super(message);
    this.name = "CertificateError";
  }
}

const dn = (attrs: forge.pki.CertificateField[]): string =>
  attrs.map((a) => `${a.shortName ?? a.name}=${String(a.value)}`).join(", ");

/** Loads a PKCS#12 (.p12/.pfx) bundle. The passphrase is never logged or echoed in errors. */
export function loadPkcs12(source: Buffer, passphrase: string): LoadedCertificate {
  let p12: forge.pkcs12.Pkcs12Pfx;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(forge.util.createBuffer(source.toString("binary"))), false, passphrase);
  } catch {
    throw new CertificateError("CERTIFICATE_INVALID", "The PKCS#12 file could not be read: wrong passphrase or corrupt file.");
  }

  const keyBags = [
    ...(p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] ?? []),
    ...(p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] ?? []),
  ];
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] ?? [];
  const key = keyBags[0]?.key as forge.pki.rsa.PrivateKey | undefined;
  if (!key) throw new CertificateError("CERTIFICATE_INVALID", "The PKCS#12 file has no RSA private key.");

  // the signing certificate is the one whose public key matches the private key
  const cert = certBags
    .map((b) => b.cert)
    .find((c): c is forge.pki.Certificate => Boolean(c) && (c!.publicKey as forge.pki.rsa.PublicKey).n.compareTo(key.n) === 0);
  if (!cert) throw new CertificateError("CERTIFICATE_INVALID", "No certificate in the PKCS#12 file matches its private key.");

  return {
    privateKeyPem: forge.pki.privateKeyToPem(key),
    certificatePem: forge.pki.certificateToPem(cert),
    serial: cert.serialNumber.toUpperCase(),
    issuer: dn(cert.issuer.attributes),
    subject: dn(cert.subject.attributes),
    notBefore: cert.validity.notBefore,
    notAfter: cert.validity.notAfter,
    isTest: false,
  };
}

export function loadPkcs12File(path: string, passphrase: string): LoadedCertificate {
  return loadPkcs12(readFileSync(path), passphrase);
}

/** Reads EASYSIGN_P12_PATH / EASYSIGN_P12_PASSPHRASE. Returns undefined when no certificate is configured. */
export function loadCertificateFromEnv(env: NodeJS.ProcessEnv = process.env): LoadedCertificate | undefined {
  const path = env.EASYSIGN_P12_PATH;
  if (!path) return undefined;
  if (!env.EASYSIGN_P12_PASSPHRASE) throw new CertificateError("CERTIFICATE_INVALID", "EASYSIGN_P12_PATH is set but EASYSIGN_P12_PASSPHRASE is empty.");
  return loadPkcs12File(path, env.EASYSIGN_P12_PASSPHRASE);
}

export interface TestCertificateOptions {
  notBefore?: Date;
  notAfter?: Date;
}

/**
 * Ephemeral self-signed certificate for the test environment ONLY. Its subject says so; it is not issued by any
 * trust service and the signing engine refuses to use it for production.
 */
export function generateTestCertificate(options: TestCertificateOptions = {}): LoadedCertificate {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(10));
  cert.validity.notBefore = options.notBefore ?? new Date(Date.now() - 60_000);
  cert.validity.notAfter = options.notAfter ?? new Date(Date.now() + 24 * 3600_000);
  const attrs = [
    { name: "commonName", value: "EasySign TEST - NOT VALID FOR PRODUCTION" },
    { name: "organizationName", value: "EasySign test fixture" },
    { name: "countryName", value: "DO" },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey),
    certificatePem: forge.pki.certificateToPem(cert),
    serial: cert.serialNumber.toUpperCase(),
    issuer: dn(cert.issuer.attributes),
    subject: dn(cert.subject.attributes),
    notBefore: cert.validity.notBefore,
    notAfter: cert.validity.notAfter,
    isTest: true,
  };
}

/** Test helper: wraps a loaded certificate back into a PKCS#12 buffer. */
export function toPkcs12(cert: LoadedCertificate, passphrase: string): Buffer {
  const key = forge.pki.privateKeyFromPem(cert.privateKeyPem);
  const crt = forge.pki.certificateFromPem(cert.certificatePem);
  const der = forge.asn1.toDer(forge.pkcs12.toPkcs12Asn1(key, [crt], passphrase, { algorithm: "3des" })).getBytes();
  return Buffer.from(der, "binary");
}

export function assertUsable(cert: LoadedCertificate, now: Date = new Date()): void {
  if (now < cert.notBefore) throw new CertificateError("CERTIFICATE_NOT_YET_VALID", `Certificate ${cert.serial} is not valid before ${cert.notBefore.toISOString()}.`);
  if (now > cert.notAfter) throw new CertificateError("CERTIFICATE_EXPIRED", `Certificate ${cert.serial} expired on ${cert.notAfter.toISOString()}.`);
}
