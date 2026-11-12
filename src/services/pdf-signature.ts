import { createHash, createPrivateKey, sign as cryptoSign, verify as cryptoVerify, X509Certificate } from "node:crypto";
import { PDFArray, PDFDict, PDFDocument, PDFHexString, PDFName, PDFNumber, PDFSignature, PDFString } from "pdf-lib";

/**
 * PAdES baseline B-B signing and cryptographic verification.
 *
 * The signature is a detached CMS SignedData (SubFilter ETSI.CAdES.detached) over the ByteRange of the PDF, with the
 * signed attributes content-type, message-digest and signing-certificate-v2. The claimed signing time goes in the M
 * entry of the signature dictionary (which is inside the ByteRange, so it is signed), not in a CMS signing-time
 * attribute, following the PAdES baseline profile.
 *
 * Not included: signature timestamp (B-T), revocation data (B-LT/B-LTA), certificate chain validation.
 */

export const PADES_SUBFILTER = "ETSI.CAdES.detached";
export const PADES_PROFILE = "PAdES-B-B";
/** Bytes reserved for the DER-encoded CMS inside /Contents. */
const SIGNATURE_RESERVED_BYTES = 8192;
const BYTE_RANGE_PLACEHOLDER = 9999999999;

export class PdfSignatureError extends Error {
  constructor(
    public readonly code: "PDF_INVALID" | "PDF_ALREADY_SIGNED" | "PDF_SIGNATURE_TOO_LARGE" | "PDF_KEY_UNSUPPORTED",
    message: string
  ) {
    super(message);
    this.name = "PdfSignatureError";
  }
}

// ---------------------------------------------------------------------------------------------------------------------
// Minimal DER encoder / reader (only what CMS SignedData needs)
// ---------------------------------------------------------------------------------------------------------------------

function derLength(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

const seq = (...parts: Buffer[]) => tlv(0x30, ...parts);
const set = (...parts: Buffer[]) => tlv(0x31, ...parts);
const octets = (b: Buffer) => tlv(0x04, b);
const DER_NULL = Buffer.from([0x05, 0x00]);
const INT_1 = Buffer.from([0x02, 0x01, 0x01]);

function oid(dotted: string): Buffer {
  const arcs = dotted.split(".").map(Number);
  const body: number[] = [arcs[0] * 40 + arcs[1]];
  for (const arc of arcs.slice(2)) {
    const chunk = [arc & 0x7f];
    for (let v = Math.floor(arc / 128); v > 0; v = Math.floor(v / 128)) chunk.unshift((v & 0x7f) | 0x80);
    body.push(...chunk);
  }
  return tlv(0x06, Buffer.from(body));
}

const OID = {
  data: oid("1.2.840.113549.1.7.1"),
  signedData: oid("1.2.840.113549.1.7.2"),
  contentType: oid("1.2.840.113549.1.9.3"),
  messageDigest: oid("1.2.840.113549.1.9.4"),
  signingCertificateV2: oid("1.2.840.113549.1.9.16.2.47"),
  rsaEncryption: oid("1.2.840.113549.1.1.1"),
  sha256WithRsa: oid("1.2.840.113549.1.1.11"),
  sha384WithRsa: oid("1.2.840.113549.1.1.12"),
  sha512WithRsa: oid("1.2.840.113549.1.1.13"),
  sha256: oid("2.16.840.1.101.3.4.2.1"),
  sha384: oid("2.16.840.1.101.3.4.2.2"),
  sha512: oid("2.16.840.1.101.3.4.2.3"),
};

interface Tlv {
  tag: number;
  start: number;
  contentStart: number;
  end: number;
}

function readTlv(buf: Buffer, offset: number, limit: number = buf.length): Tlv {
  if (offset + 2 > limit) throw new Error("truncated DER element");
  const tag = buf[offset];
  if ((tag & 0x1f) === 0x1f) throw new Error("multi-byte DER tags are not supported");
  let length = buf[offset + 1];
  let p = offset + 2;
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n === 0 || n > 4) throw new Error("indefinite or oversized DER length");
    if (p + n > limit) throw new Error("truncated DER length");
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + buf[p++];
  }
  if (p + length > limit) throw new Error("DER element exceeds its container");
  return { tag, start: offset, contentStart: p, end: p + length };
}

function children(buf: Buffer, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let p = parent.contentStart; p < parent.end; ) {
    const child = readTlv(buf, p, parent.end);
    out.push(child);
    p = child.end;
  }
  return out;
}

const raw = (buf: Buffer, t: Tlv) => buf.subarray(t.start, t.end);
const content = (buf: Buffer, t: Tlv) => buf.subarray(t.contentStart, t.end);

function expect(buf: Buffer, t: Tlv | undefined, tag: number, what: string): Tlv {
  if (!t || t.tag !== tag) throw new Error(`CMS: expected ${what}`);
  return t;
}

/** Raw DER of the issuer Name and the serial INTEGER of an X.509 certificate. */
function issuerAndSerialOf(certDer: Buffer): { issuer: Buffer; serial: Buffer } {
  const tbs = children(certDer, readTlv(certDer, 0))[0];
  const fields = children(certDer, tbs);
  const i = fields[0].tag === 0xa0 ? 1 : 0; // optional [0] version
  return { serial: Buffer.from(raw(certDer, fields[i])), issuer: Buffer.from(raw(certDer, fields[i + 2])) };
}

/** Serial number as the hex of its raw INTEGER bytes, the form the certificate store reports (node prints a sign for high-bit serials). */
function readSerialHex(certDer: Buffer): string {
  const { serial } = issuerAndSerialOf(certDer);
  return content(serial, readTlv(serial, 0)).toString("hex").toUpperCase();
}

// ---------------------------------------------------------------------------------------------------------------------
// CMS (CAdES-BES) detached signature
// ---------------------------------------------------------------------------------------------------------------------

export interface SigningIdentity {
  privateKeyPem: string;
  certificatePem: string;
}

/** Builds a detached CMS SignedData (RSA PKCS#1 v1.5 + SHA-256) with the CAdES signed attributes. */
export function buildCadesDetachedSignature(data: Buffer, identity: SigningIdentity): Buffer {
  const key = createPrivateKey(identity.privateKeyPem);
  if (key.asymmetricKeyType !== "rsa") throw new PdfSignatureError("PDF_KEY_UNSUPPORTED", "Only RSA signing keys are supported.");
  const certDer = new X509Certificate(identity.certificatePem).raw;
  const { issuer, serial } = issuerAndSerialOf(certDer);

  const attribute = (type: Buffer, value: Buffer) => seq(type, set(value));
  const essCertIdV2 = seq(octets(createHash("sha256").update(certDer).digest()), seq(seq(tlv(0xa4, issuer)), serial)); // hashAlgorithm omitted = SHA-256 (DEFAULT)
  const attributes = [
    attribute(OID.contentType, OID.data),
    attribute(OID.messageDigest, octets(createHash("sha256").update(data).digest())),
    attribute(OID.signingCertificateV2, seq(seq(essCertIdV2))),
  ].sort(Buffer.compare); // DER SET OF ordering

  // the signature covers the attributes encoded as an explicit SET OF, they travel as [0] IMPLICIT
  const signature = cryptoSign("sha256", set(...attributes), key);
  const digestAlgorithm = seq(OID.sha256, DER_NULL);
  const signerInfo = seq(INT_1, seq(issuer, serial), digestAlgorithm, tlv(0xa0, ...attributes), seq(OID.rsaEncryption, DER_NULL), octets(signature));
  const signedData = seq(INT_1, set(digestAlgorithm), seq(OID.data), tlv(0xa0, certDer), set(signerInfo));
  return seq(OID.signedData, tlv(0xa0, signedData));
}

export interface CmsVerification {
  errors: string[];
  certificate?: X509Certificate;
  digestAlgorithm?: string;
  /** Hex of the message-digest signed attribute. */
  messageDigest?: string;
  hasSigningCertificateV2: boolean;
}

const HASH_BY_OID: Array<[Buffer, string]> = [
  [OID.sha256, "sha256"],
  [OID.sha384, "sha384"],
  [OID.sha512, "sha512"],
];
const hashName = (oidTlv: Buffer) => HASH_BY_OID.find(([o]) => o.equals(oidTlv))?.[1];

/** Verifies a detached CMS SignedData against `data` using the signer certificate embedded in the CMS. */
export function verifyCadesDetachedSignature(cms: Buffer, data: Buffer): CmsVerification {
  const result: CmsVerification = { errors: [], hasSigningCertificateV2: false };
  const fail = (message: string) => {
    result.errors.push(message);
    return result;
  };
  try {
    const contentInfo = children(cms, expect(cms, readTlv(cms, 0), 0x30, "ContentInfo"));
    if (!raw(cms, contentInfo[0]).equals(OID.signedData)) return fail("CMS: content type is not SignedData");
    const signedData = expect(cms, children(cms, expect(cms, contentInfo[1], 0xa0, "[0] SignedData"))[0], 0x30, "SignedData");
    const sd = children(cms, signedData);
    const encap = children(cms, expect(cms, sd[2], 0x30, "EncapsulatedContentInfo"));
    if (encap.length !== 1) return fail("CMS: the signature is not detached (it carries its own content)");
    const certSet = sd.find((t) => t.tag === 0xa0);
    const signerInfos = children(cms, expect(cms, sd[sd.length - 1], 0x31, "SignerInfos"));
    if (signerInfos.length !== 1) return fail(`CMS: expected exactly one signer, found ${signerInfos.length}`);

    const si = children(cms, expect(cms, signerInfos[0], 0x30, "SignerInfo"));
    const sid = expect(cms, si[1], 0x30, "IssuerAndSerialNumber signer identifier");
    const digestOid = raw(cms, children(cms, expect(cms, si[2], 0x30, "digest algorithm"))[0]);
    const signedAttrs = expect(cms, si[3], 0xa0, "signed attributes");
    const signatureOid = raw(cms, children(cms, expect(cms, si[4], 0x30, "signature algorithm"))[0]);
    const signature = content(cms, expect(cms, si[5], 0x04, "signature value"));

    const digest = hashName(digestOid);
    if (!digest) return fail("CMS: unsupported digest algorithm (only SHA-256/384/512)");
    result.digestAlgorithm = digest;
    const rsaOids: Array<[Buffer, string | undefined]> = [[OID.rsaEncryption, undefined], [OID.sha256WithRsa, "sha256"], [OID.sha384WithRsa, "sha384"], [OID.sha512WithRsa, "sha512"]];
    const sigAlg = rsaOids.find(([o]) => o.equals(signatureOid));
    if (!sigAlg) return fail("CMS: unsupported signature algorithm (only RSA PKCS#1 v1.5)");
    if (sigAlg[1] && sigAlg[1] !== digest) return fail("CMS: signature algorithm does not match the digest algorithm");

    // signer certificate: the embedded one whose issuer and serial match the signer identifier
    const [sidIssuer, sidSerial] = children(cms, sid).map((t) => raw(cms, t));
    const certDer = (certSet ? children(cms, certSet) : [])
      .filter((t) => t.tag === 0x30)
      .map((t) => Buffer.from(raw(cms, t)))
      .find((der) => {
        try {
          const ids = issuerAndSerialOf(der);
          return ids.issuer.equals(sidIssuer) && ids.serial.equals(sidSerial);
        } catch {
          return false;
        }
      });
    if (!certDer) return fail("CMS: the signer certificate is not embedded in the signature");
    const certificate = new X509Certificate(certDer);
    result.certificate = certificate;
    if (certificate.publicKey.asymmetricKeyType !== "rsa") return fail("CMS: the signer certificate does not hold an RSA key");

    // signed attributes
    const attrs = new Map<string, Buffer[]>();
    for (const a of children(cms, signedAttrs)) {
      const [type, values] = children(cms, expect(cms, a, 0x30, "Attribute"));
      const key = raw(cms, type).toString("hex");
      if (attrs.has(key)) return fail("CMS: duplicated signed attribute");
      attrs.set(key, children(cms, expect(cms, values, 0x31, "attribute values")).map((v) => Buffer.from(raw(cms, v))));
    }
    const single = (o: Buffer) => {
      const v = attrs.get(o.toString("hex"));
      return v && v.length === 1 ? v[0] : undefined;
    };
    if (!single(OID.contentType)?.equals(OID.data)) result.errors.push("CMS: content-type signed attribute is missing or is not id-data");
    const md = single(OID.messageDigest);
    if (!md || md[0] !== 0x04) {
      result.errors.push("CMS: message-digest signed attribute is missing");
    } else {
      const signedDigest = content(md, readTlv(md, 0));
      result.messageDigest = signedDigest.toString("hex");
      if (!signedDigest.equals(createHash(digest).update(data).digest())) result.errors.push("document digest does not match the signed message-digest: the signed content was modified");
    }
    const scv2 = single(OID.signingCertificateV2);
    if (scv2) {
      result.hasSigningCertificateV2 = true;
      const essCertId = children(scv2, children(scv2, children(scv2, readTlv(scv2, 0))[0])[0]);
      const certHashAlg = essCertId[0].tag === 0x30 ? hashName(raw(scv2, children(scv2, essCertId[0])[0])) : "sha256";
      const certHash = essCertId.find((t) => t.tag === 0x04);
      if (!certHashAlg || !certHash || !content(scv2, certHash).equals(createHash(certHashAlg).update(certDer).digest())) {
        result.errors.push("CMS: signing-certificate-v2 does not match the signer certificate");
      }
    }

    const signedBytes = Buffer.concat([Buffer.from([0x31]), raw(cms, signedAttrs).subarray(1)]);
    if (!cryptoVerify(digest, signedBytes, certificate.publicKey, signature)) result.errors.push("signature value does not verify with the signer certificate");
    return result;
  } catch (e) {
    return fail(`CMS: malformed signature (${(e as Error).message})`);
  }
}

// ---------------------------------------------------------------------------------------------------------------------
// PDF signing
// ---------------------------------------------------------------------------------------------------------------------

export interface PdfSignOptions {
  identity: SigningIdentity;
  signingTime: Date;
  reason: string;
  location?: string;
  contactInfo?: string;
}

export interface SignedPdf {
  signedPdf: Buffer;
  byteRange: [number, number, number, number];
  /** SHA-256 (hex) of the bytes covered by the ByteRange; it is the message-digest inside the CMS. */
  byteRangeDigest: string;
}

const isPdf = (bytes: Buffer) => bytes.subarray(0, 1024).includes("%PDF-");

/**
 * Adds one invisible signature field and signs the whole file. The document is re-serialized (not an incremental
 * update), so a PDF that already carries a signature is rejected instead of silently invalidating it.
 */
export async function signPdfDocument(pdf: Buffer, options: PdfSignOptions): Promise<SignedPdf> {
  if (!isPdf(pdf)) throw new PdfSignatureError("PDF_INVALID", "The document is not a PDF.");
  if (pdf.includes("/ByteRange")) throw new PdfSignatureError("PDF_ALREADY_SIGNED", "The PDF already carries a signature; adding another one is not supported.");

  let doc: PDFDocument;
  try {
    doc = await PDFDocument.load(pdf, { updateMetadata: false });
  } catch (e) {
    throw new PdfSignatureError("PDF_INVALID", `The PDF could not be read (corrupt or encrypted): ${(e as Error).message}`);
  }
  const page = doc.getPages()[0];
  if (!page) throw new PdfSignatureError("PDF_INVALID", "The PDF has no pages.");

  const acroFormKey = PDFName.of("AcroForm");
  if (doc.catalog.has(acroFormKey) && doc.getForm().getFields().some((f) => f instanceof PDFSignature && f.acroField.dict.has(PDFName.of("V")))) {
    throw new PdfSignatureError("PDF_ALREADY_SIGNED", "The PDF already carries a signature; adding another one is not supported.");
  }

  const ctx = doc.context;
  const byteRange = PDFArray.withContext(ctx);
  byteRange.push(PDFNumber.of(0));
  for (let i = 0; i < 3; i++) byteRange.push(PDFNumber.of(BYTE_RANGE_PLACEHOLDER));
  const signatureDict = ctx.obj({ Type: "Sig", Filter: "Adobe.PPKLite", SubFilter: PADES_SUBFILTER });
  signatureDict.set(PDFName.of("ByteRange"), byteRange);
  signatureDict.set(PDFName.of("Contents"), PDFHexString.of("0".repeat(SIGNATURE_RESERVED_BYTES * 2)));
  signatureDict.set(PDFName.of("M"), PDFString.fromDate(options.signingTime));
  signatureDict.set(PDFName.of("Reason"), PDFHexString.fromText(options.reason));
  if (options.location) signatureDict.set(PDFName.of("Location"), PDFHexString.fromText(options.location));
  if (options.contactInfo) signatureDict.set(PDFName.of("ContactInfo"), PDFHexString.fromText(options.contactInfo));
  const signatureRef = ctx.register(signatureDict);

  const widget = ctx.obj({ Type: "Annot", Subtype: "Widget", FT: "Sig", Rect: [0, 0, 0, 0], F: 132 });
  widget.set(PDFName.of("V"), signatureRef);
  widget.set(PDFName.of("T"), PDFString.of("EasySignSignature1"));
  widget.set(PDFName.of("P"), page.ref);
  const widgetRef = ctx.register(widget);

  const annots = page.node.lookupMaybe(PDFName.of("Annots"), PDFArray);
  if (annots) annots.push(widgetRef);
  else page.node.set(PDFName.of("Annots"), ctx.obj([widgetRef]));

  const acroForm = doc.catalog.lookupMaybe(acroFormKey, PDFDict);
  if (acroForm) {
    const fields = acroForm.lookupMaybe(PDFName.of("Fields"), PDFArray);
    if (fields) fields.push(widgetRef);
    else acroForm.set(PDFName.of("Fields"), ctx.obj([widgetRef]));
    acroForm.set(PDFName.of("SigFlags"), PDFNumber.of(3));
  } else {
    doc.catalog.set(acroFormKey, ctx.obj({ SigFlags: 3, Fields: [widgetRef] }));
  }

  const out = Buffer.from(await doc.save({ useObjectStreams: false, addDefaultPage: false, updateFieldAppearances: false }));

  // locate the two placeholders; both must be unique
  const contentsNeedle = Buffer.from(`<${"0".repeat(SIGNATURE_RESERVED_BYTES * 2)}>`, "latin1");
  const contentsStart = out.indexOf(contentsNeedle);
  const rangeMatches = [...out.toString("latin1").matchAll(new RegExp(`/ByteRange\\s*\\[\\s*0\\s+${BYTE_RANGE_PLACEHOLDER}\\s+${BYTE_RANGE_PLACEHOLDER}\\s+${BYTE_RANGE_PLACEHOLDER}\\s*\\]`, "g"))];
  if (contentsStart < 0 || out.indexOf(contentsNeedle, contentsStart + 1) >= 0 || rangeMatches.length !== 1) {
    throw new PdfSignatureError("PDF_INVALID", "The signature placeholder could not be located in the serialized PDF.");
  }
  const contentsEnd = contentsStart + contentsNeedle.length;
  const range: [number, number, number, number] = [0, contentsStart, contentsEnd, out.length - contentsEnd];
  const rangeText = `/ByteRange [${range.join(" ")}]`;
  out.write(rangeText.padEnd(rangeMatches[0][0].length, " "), rangeMatches[0].index!, "latin1");

  const signedBytes = Buffer.concat([out.subarray(0, contentsStart), out.subarray(contentsEnd)]);
  const cms = buildCadesDetachedSignature(signedBytes, options.identity);
  if (cms.length > SIGNATURE_RESERVED_BYTES) throw new PdfSignatureError("PDF_SIGNATURE_TOO_LARGE", `The CMS signature (${cms.length} bytes) exceeds the reserved space.`);
  out.write(cms.toString("hex"), contentsStart + 1, "latin1");

  return { signedPdf: out, byteRange: range, byteRangeDigest: createHash("sha256").update(signedBytes).digest("hex") };
}

// ---------------------------------------------------------------------------------------------------------------------
// PDF verification
// ---------------------------------------------------------------------------------------------------------------------

export interface PdfSignatureVerification {
  valid: boolean;
  errors: string[];
  subFilter?: string;
  /** Signing time claimed by the signer (M entry). It is signed but it is NOT a trusted timestamp. */
  signingTime?: string;
  byteRange?: [number, number, number, number];
  /** True when the ByteRange covers the whole file except the signature value. */
  coversWholeDocument: boolean;
  digestAlgorithm?: string;
  /** Digest (hex) of the signed bytes as stated inside the signature. */
  documentDigest?: string;
  certificate?: { subject: string; issuer: string; serial: string; notBefore: string; notAfter: string; pem: string };
  /** The certificate chain, revocation status and timestamps are not evaluated by this function. */
  trust: "NOT_EVALUATED";
}

export interface PdfVerifyOptions {
  /** When given, the embedded signer certificate must be exactly this one. */
  expectedCertificatePem?: string;
}

function pdfDateToIso(d: string): string | undefined {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:Z|([+-])(\d{2})'?(\d{2})?'?)?/.exec(d);
  if (!m) return undefined;
  const offset = m[7] ? `${m[7]}${m[8]}:${m[9] ?? "00"}` : "Z";
  const date = new Date(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${offset}`);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

/**
 * Cryptographic verification of the single signature of a PDF: extracts ByteRange and the CMS, checks that the range
 * covers the whole file, that the digest of the signed bytes matches, and that the signature value verifies with the
 * embedded certificate. It does not decide whether that certificate is trusted.
 */
export function verifyPdfSignature(pdf: Buffer, options: PdfVerifyOptions = {}): PdfSignatureVerification {
  const result: PdfSignatureVerification = { valid: false, errors: [], coversWholeDocument: false, trust: "NOT_EVALUATED" };
  const fail = (message: string) => {
    result.errors.push(message);
    return result;
  };
  if (!isPdf(pdf)) return fail("the document is not a PDF");

  const text = pdf.toString("latin1");
  const matches = [...text.matchAll(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g)];
  if (matches.length === 0) return fail("the PDF has no signature");
  if (matches.length > 1) return fail(`the PDF has ${matches.length} signatures; only single-signature documents are supported`);

  const [a, b, c, d] = matches[0].slice(1, 5).map(Number);
  result.byteRange = [a, b, c, d];
  if (a !== 0 || b <= 0 || c <= b || c + d > pdf.length) return fail("ByteRange is inconsistent with the file");
  result.coversWholeDocument = c + d === pdf.length;
  if (!result.coversWholeDocument) result.errors.push("ByteRange does not cover the whole file: there is content outside the signature");

  const hex = text.slice(b + 1, c - 1);
  if (text[b] !== "<" || text[c - 1] !== ">" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex) || !/\/Contents\s*$/.test(text.slice(Math.max(0, b - 32), b))) {
    return fail("the gap of ByteRange is not exactly the /Contents signature value");
  }
  const index = matches[0].index!;
  if (index >= b && index < c) return fail("ByteRange is inconsistent with the file");

  // signature dictionary entries (they sit inside the signed range)
  const dictStart = Math.max(0, text.lastIndexOf(" obj", index));
  const dictEnd = text.indexOf("endobj", index);
  const dict = text.slice(dictStart, dictEnd < 0 ? undefined : dictEnd);
  // the dictionary must be the value (/V) of a signature field: a CMS parked in an unreferenced object is not a signature of the document
  const objectId = /(\d+)\s+(\d+)\s*$/.exec(text.slice(Math.max(0, dictStart - 24), dictStart));
  if (!objectId || !new RegExp(`/V\\s+${objectId[1]}\\s+${objectId[2]}\\s+R\\b`).test(text) || !/\/FT\s*\/Sig\b/.test(text)) {
    result.errors.push("the signature dictionary is not referenced by a signature field (/FT /Sig with /V) readable in the file");
  }
  result.subFilter = /\/SubFilter\s*\/([A-Za-z0-9.]+)/.exec(dict)?.[1];
  const m = /\/M\s*\(D:([0-9Z+\-']+)\)/.exec(dict);
  result.signingTime = m ? pdfDateToIso(m[1]) : undefined;
  if (result.subFilter !== PADES_SUBFILTER && result.subFilter !== "adbe.pkcs7.detached") {
    return fail(`unsupported SubFilter ${result.subFilter ?? "(none)"}; only ${PADES_SUBFILTER} and adbe.pkcs7.detached`);
  }

  let cms: Buffer;
  try {
    const padded = Buffer.from(hex, "hex");
    cms = padded.subarray(0, readTlv(padded, 0).end); // drop the zero padding of the placeholder
  } catch (e) {
    return fail(`CMS: malformed signature (${(e as Error).message})`);
  }

  const signedBytes = Buffer.concat([pdf.subarray(a, a + b), pdf.subarray(c, c + d)]);
  const check = verifyCadesDetachedSignature(cms, signedBytes);
  result.errors.push(...check.errors);
  result.digestAlgorithm = check.digestAlgorithm;
  result.documentDigest = check.messageDigest;

  const cert = check.certificate;
  if (cert) {
    result.certificate = {
      subject: cert.subject.replace(/\n/g, ", "),
      issuer: cert.issuer.replace(/\n/g, ", "),
      serial: readSerialHex(cert.raw),
      notBefore: new Date(cert.validFrom).toISOString(),
      notAfter: new Date(cert.validTo).toISOString(),
      pem: cert.toString(),
    };
    if (result.subFilter === PADES_SUBFILTER && !check.hasSigningCertificateV2) result.errors.push("CMS: signing-certificate-v2 is required for ETSI.CAdES.detached");
    if (options.expectedCertificatePem) {
      let same = false;
      try {
        same = new X509Certificate(options.expectedCertificatePem).raw.equals(cert.raw);
      } catch { /* an unreadable expected certificate never matches */ }
      if (!same) result.errors.push("the signer certificate is not the expected certificate");
    }
    if (result.signingTime) {
      const at = new Date(result.signingTime).getTime();
      if (at < new Date(cert.validFrom).getTime() || at > new Date(cert.validTo).getTime()) result.errors.push("the claimed signing time is outside the validity period of the signer certificate");
    }
  }

  result.valid = result.errors.length === 0;
  return result;
}
