import { createHash, randomBytes } from "node:crypto";

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
}

export interface PdfSigningRequest {
  documentId: string;
  tenantId: string;
  documentHash: string;
  signerName: string;
  signerEmail: string;
  reason?: string;
  location?: string;
}

export interface PdfSigningResult {
  signatureId: string;
  documentId: string;
  signatureHash: string;
  tamperEvidentChain: string;
  timestampToken: string;
  signedAt: string;
}

export class SigningEngine {
  private readonly defaultCertificateSerial = "4A7B9C1E2F3D4E5F6A7B8C9D";
  private readonly defaultIssuer = "CN=AVANSI CA - G2, O=AVANSI S.R.L., C=DO";

  public async signEcfXml(
    request: EcfSigningRequest,
    progressCallback?: (p: number) => void
  ): Promise<EcfSigningResult> {
    progressCallback?.(15);

    const rawXml =
      request.rawXml ||
      `<ECF><Encabezado><Emisor><RNCEmisor>${request.rncEmisor}</RNCEmisor></Emisor><IdDoc><eNCF>${request.eNcf}</eNCF></IdDoc><Totales><MontoTotal>${request.amountTotal ?? 1000.0}</MontoTotal></Totales></Encabezado></ECF>`;

    progressCallback?.(40);

    const digestValue = createHash("sha256").update(rawXml, "utf8").digest("base64");

    progressCallback?.(70);

    const signatureValue = createHash("sha256")
      .update(digestValue + request.rncEmisor + request.eNcf, "utf8")
      .digest("base64");

    const securityCode = createHash("sha256")
      .update(signatureValue)
      .digest("hex")
      .substring(0, 6)
      .toUpperCase();

    const signedAt = new Date().toISOString();
    const signatureId = `sig-${createHash("md5").update(request.eNcf + signedAt).digest("hex")}`;

    const signedXml = `${rawXml}
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="${signatureId}">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <Reference URI="#${request.eNcf}">
      <Transforms>
        <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
      </Transforms>
      <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <DigestValue>${digestValue}</DigestValue>
    </Reference>
  </SignedInfo>
  <SignatureValue>${signatureValue}</SignatureValue>
  <KeyInfo>
    <X509Data>
      <X509Certificate>${Buffer.from(`CERT-${request.rncEmisor}-${this.defaultCertificateSerial}`).toString("base64")}</X509Certificate>
    </X509Data>
  </KeyInfo>
</Signature>`;

    progressCallback?.(100);

    return {
      signatureId,
      eNcf: request.eNcf,
      digestValue,
      signatureValue,
      certificateSerial: this.defaultCertificateSerial,
      certificateIssuer: this.defaultIssuer,
      signedXml,
      signedAt,
      canonicalizationMethod: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
      signatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      securityCode,
    };
  }

  public async signPdf(
    request: PdfSigningRequest,
    progressCallback?: (p: number) => void
  ): Promise<PdfSigningResult> {
    progressCallback?.(25);
    const signedAt = new Date().toISOString();

    const signatureHash = createHash("sha256")
      .update(request.documentHash + request.signerEmail + signedAt)
      .digest("hex");

    progressCallback?.(65);

    const tamperEvidentChain = createHash("sha256")
      .update(signatureHash + request.tenantId)
      .digest("hex");

    const timestampToken = createHash("sha256")
      .update(tamperEvidentChain + Date.now().toString())
      .digest("base64");

    progressCallback?.(100);

    return {
      signatureId: `pdf-sig-${randomBytes(8).toString("hex")}`,
      documentId: request.documentId,
      signatureHash,
      tamperEvidentChain,
      timestampToken,
      signedAt,
    };
  }
}
