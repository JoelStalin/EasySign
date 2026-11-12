import { createHash, randomBytes } from "node:crypto";
import { DOMParser } from "@xmldom/xmldom";
import { SignedXml } from "xml-crypto";
import {
  assertUsable,
  CertificateError,
  generateTestCertificate,
  loadCertificateFromEnv,
  type LoadedCertificate,
} from "./certificate-store.js";
import { PADES_PROFILE, PADES_SUBFILTER, signPdfDocument, verifyPdfSignature, type PdfSignatureVerification } from "./pdf-signature.js";

export interface EcfSigningRequest {
  documentId: string;
  tenantId: string;
  rncEmisor: string;
  eNcf: string;
  rawXml?: string;
  amountTotal?: number;
  environment?: "test" | "production";
}

export interface EcfSigningResult {
  signatureId: string;
  eNcf: string;
  digestValue: string;
  signatureValue: string;
  certificateSerial: string;
  certificateIssuer: string;
  signedXml: string;
  signedAt: string;
  canonicalizationMethod: string;
  signatureMethod: string;
  securityCode: string;
  /** True when signed with the ephemeral test certificate: the result has no legal value. */
  testCertificate: boolean;
}

export interface EcfVerificationResult {
  valid: boolean;
  errors: string[];
}

export interface PdfSigningRequest {
  documentId: string;
  tenantId: string;
  /** The PDF to sign, base64-encoded (jobs travel as JSON). */
  pdfBase64: string;
  /** Optional SHA-256 (lowercase hex) the caller expects for the PDF; signing is refused when it does not match. */
  documentHash?: string;
  signerName: string;
  signerEmail: string;
  reason?: string;
  location?: string;
  environment?: "test" | "production";
}

export interface PdfSigningResult {
  signatureId: string;
  documentId: string;
  /** The signed PDF, base64-encoded. */
  signedPdfBase64: string;
  /** SHA-256 (hex) of the PDF as received, before signing. */
  documentHash: string;
  /** SHA-256 (hex) of the signed PDF file. */
  signedDocumentHash: string;
  /** SHA-256 (hex) of the bytes covered by the signature (the message-digest inside the CMS). */
  byteRangeDigest: string;
  byteRange: [number, number, number, number];
  /** Signing time claimed by this server (M entry of the signature). It is NOT a trusted timestamp. */
  signedAt: string;
  subFilter: string;
  /** PAdES-B-B: no signature timestamp and no embedded revocation data. */
  profile: string;
  trustedTimestamp: false;
  signatureMethod: string;
  certificateSerial: string;
  certificateIssuer: string;
  certificateSubject: string;
  /** True when signed with the ephemeral test certificate: the result has no legal value. */
  testCertificate: boolean;
}

export interface SigningEngineOptions {
  /** Certificate for real signatures. Defaults to EASYSIGN_P12_PATH / EASYSIGN_P12_PASSPHRASE when set. */
  certificate?: LoadedCertificate;
  /** Clock override for tests. */
  now?: () => Date;
}

const C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";

const escapeXml = (s: string) => s.replace(/[<>&"']/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&apos;" })[c]!);

export class SigningEngine {
  private readonly configured?: LoadedCertificate;
  private testCertificate?: LoadedCertificate;
  private readonly now: () => Date;

  constructor(options: SigningEngineOptions = {}) {
    this.configured = options.certificate ?? loadCertificateFromEnv();
    this.now = options.now ?? (() => new Date());
  }

  /** Picks the certificate for an environment. Production never signs with a missing or test certificate. */
  private certificateFor(environment: "test" | "production"): LoadedCertificate {
    if (environment === "production") {
      if (!this.configured || this.configured.isTest) {
        throw new CertificateError("CERTIFICATE_REQUIRED", "Production signing requires a real certificate (EASYSIGN_P12_PATH / EASYSIGN_P12_PASSPHRASE).");
      }
      assertUsable(this.configured, this.now());
      return this.configured;
    }
    if (this.configured) {
      assertUsable(this.configured, this.now());
      return this.configured;
    }
    this.testCertificate ??= generateTestCertificate({ notBefore: new Date(this.now().getTime() - 60_000), notAfter: new Date(this.now().getTime() + 24 * 3600_000) });
    return this.testCertificate;
  }

  public async signEcfXml(request: EcfSigningRequest, progressCallback?: (p: number) => void): Promise<EcfSigningResult> {
    progressCallback?.(10);
    const cert = this.certificateFor(request.environment ?? "test");

    const rawXml =
      request.rawXml ||
      `<ECF><Encabezado><Emisor><RNCEmisor>${escapeXml(request.rncEmisor)}</RNCEmisor></Emisor><IdDoc><eNCF>${escapeXml(request.eNcf)}</eNCF></IdDoc><Totales><MontoTotal>${request.amountTotal ?? 1000.0}</MontoTotal></Totales></Encabezado></ECF>`;
    if (new DOMParser({ onError: () => undefined }).parseFromString(rawXml, "text/xml").documentElement?.nodeName === undefined) {
      throw new Error("rawXml is not well-formed XML.");
    }
    progressCallback?.(40);

    const signedAt = this.now().toISOString();
    const signatureId = `sig-${createHash("sha256").update(request.eNcf + signedAt + randomBytes(4).toString("hex")).digest("hex").slice(0, 32)}`;

    const sig = new SignedXml({
      privateKey: cert.privateKeyPem,
      publicCert: cert.certificatePem,
      canonicalizationAlgorithm: C14N,
      signatureAlgorithm: RSA_SHA256,
      getKeyInfoContent: SignedXml.getKeyInfoContent,
    });
    sig.addReference({ xpath: "/*", transforms: [ENVELOPED, C14N], digestAlgorithm: SHA256 });
    progressCallback?.(70);
    sig.computeSignature(rawXml, { location: { reference: "/*", action: "append" }, attrs: { Id: signatureId } });
    const signedXml = sig.getSignedXml();

    const doc = new DOMParser().parseFromString(signedXml, "text/xml");
    const digestValue = doc.getElementsByTagNameNS(DSIG_NS, "DigestValue")[0]?.textContent?.trim() ?? "";
    const signatureValue = doc.getElementsByTagNameNS(DSIG_NS, "SignatureValue")[0]?.textContent?.replace(/\s+/g, "") ?? "";
    progressCallback?.(100);

    return {
      signatureId,
      eNcf: request.eNcf,
      digestValue,
      signatureValue,
      certificateSerial: cert.serial,
      certificateIssuer: cert.issuer,
      signedXml,
      signedAt,
      canonicalizationMethod: C14N,
      signatureMethod: RSA_SHA256,
      // first six characters of SignatureValue; confirm against the official DGII spec before relying on it (see COMPLIANCE_MATRIX)
      securityCode: signatureValue.slice(0, 6),
      testCertificate: cert.isTest,
    };
  }

  /** Verifies the enveloped signature against the certificate embedded in KeyInfo, or `expectedCertificatePem` when given. */
  public verifyEcfXml(signedXml: string, expectedCertificatePem?: string): EcfVerificationResult {
    const errors: string[] = [];
    const doc = new DOMParser({ onError: (_l, m) => errors.push(String(m)) }).parseFromString(signedXml, "text/xml");
    const nodes = doc.getElementsByTagNameNS(DSIG_NS, "Signature");
    if (nodes.length !== 1) return { valid: false, errors: [...errors, `expected exactly one Signature element, found ${nodes.length}`] };

    const embedded = nodes[0].getElementsByTagNameNS(DSIG_NS, "X509Certificate")[0]?.textContent?.replace(/\s+/g, "");
    const publicCert = expectedCertificatePem ?? (embedded ? `-----BEGIN CERTIFICATE-----\n${embedded}\n-----END CERTIFICATE-----` : undefined);
    if (!publicCert) return { valid: false, errors: [...errors, "no certificate available to verify the signature"] };

    const check = new SignedXml({ publicCert });
    check.loadSignature(nodes[0] as unknown as Node);
    let valid = false;
    try {
      valid = check.checkSignature(signedXml);
    } catch (e) {
      errors.push((e as Error).message);
    }
    if (!valid && errors.length === 0) errors.push("signature does not match the document");
    return { valid, errors: valid ? [] : errors };
  }

  /**
   * Signs a PDF with a real PAdES-B-B signature (detached CMS, SubFilter ETSI.CAdES.detached) using the same
   * certificate rules as XML: production requires the real .p12, the test environment may use the ephemeral one.
   */
  public async signPdf(request: PdfSigningRequest, progressCallback?: (p: number) => void): Promise<PdfSigningResult> {
    progressCallback?.(10);
    const cert = this.certificateFor(request.environment ?? "test");
    if (typeof request.pdfBase64 !== "string" || request.pdfBase64.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(request.pdfBase64)) {
      throw new Error("sign_pdf requires data.pdfBase64 (the PDF to sign, base64-encoded).");
    }
    const pdf = Buffer.from(request.pdfBase64, "base64");
    const documentHash = createHash("sha256").update(pdf).digest("hex");
    if (request.documentHash !== undefined && request.documentHash !== documentHash) {
      throw new Error("DOCUMENT_MISMATCH: the SHA-256 of the PDF does not match documentHash.");
    }
    progressCallback?.(30);

    // PDF dates have one-second resolution; the evidence reports exactly the time written in the signature
    const signingTime = new Date(Math.floor(this.now().getTime() / 1000) * 1000);
    const signed = await signPdfDocument(pdf, {
      identity: cert,
      signingTime,
      reason: request.reason ?? `Documento aceptado por ${request.signerName} <${request.signerEmail}>`,
      location: request.location,
      contactInfo: request.signerEmail,
    });
    progressCallback?.(100);

    return {
      signatureId: `pdf-sig-${randomBytes(8).toString("hex")}`,
      documentId: request.documentId,
      signedPdfBase64: signed.signedPdf.toString("base64"),
      documentHash,
      signedDocumentHash: createHash("sha256").update(signed.signedPdf).digest("hex"),
      byteRangeDigest: signed.byteRangeDigest,
      byteRange: signed.byteRange,
      signedAt: signingTime.toISOString(),
      subFilter: PADES_SUBFILTER,
      profile: PADES_PROFILE,
      trustedTimestamp: false,
      signatureMethod: RSA_SHA256,
      certificateSerial: cert.serial,
      certificateIssuer: cert.issuer,
      certificateSubject: cert.subject,
      testCertificate: cert.isTest,
    };
  }

  /** Cryptographic verification of a signed PDF against its embedded certificate, or `expectedCertificatePem` when given. */
  public verifyPdf(signedPdf: Buffer, expectedCertificatePem?: string): PdfSignatureVerification {
    return verifyPdfSignature(signedPdf, { expectedCertificatePem });
  }
}
