import QRCode from "qrcode";

/**
 * Delivery of the signing link. The CLIENT chooses the channel per signer:
 *  - email / whatsapp: sent through a configured provider (ES-013). Without a provider nothing is sent and the
 *    result says so honestly (`pending_provider`) with the link so the administrator can deliver it.
 *  - link: the administrator copies the link.
 *  - qr: the link is rendered as a QR shown on screen, so the signer scans it with their phone (in-person signing).
 * The one-time token travels in the URL fragment (`#token`), which browsers never send to the server nor put in access logs.
 */

export type DeliveryChannel = "email" | "whatsapp" | "qr" | "link";
export const CHANNELS: readonly DeliveryChannel[] = ["email", "whatsapp", "qr", "link"];

export interface DeliverableToken {
  signerId: string;
  name: string;
  email: string;
  phone?: string;
  order: number;
  token: string;
  channel: DeliveryChannel;
}

export interface DeliveryProvider {
  channel: "email" | "whatsapp";
  send(message: { to: string; name: string; url: string; documentName: string }): Promise<void>;
}

export interface DeliveryResult {
  signerId: string;
  name: string;
  channel: DeliveryChannel;
  status: "sent" | "manual" | "pending_provider" | "error";
  note: string;
  /** Omitted when a provider delivered it, so the link does not travel back to the caller needlessly. */
  signingUrl?: string;
  /** SVG of the QR, only for the `qr` channel. */
  qrSvg?: string;
}

export function buildSigningUrl(baseUrl: string, requestId: string, signerId: string, token: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/sign/${requestId}/${signerId}#${token}`;
}

export async function renderQrSvg(url: string): Promise<string> {
  return QRCode.toString(url, { type: "svg", errorCorrectionLevel: "M", margin: 2, width: 320 });
}

export async function prepareDelivery(
  tokens: DeliverableToken[],
  requestId: string,
  documentName: string,
  baseUrl: string | undefined,
  providers: DeliveryProvider[] = []
): Promise<DeliveryResult[]> {
  const out: DeliveryResult[] = [];
  for (const t of tokens) {
    const base = { signerId: t.signerId, name: t.name, channel: t.channel };
    if (!baseUrl) {
      out.push({ ...base, status: "error", note: "EASYSIGN_PUBLIC_BASE_URL is not configured, so a signing link cannot be built." });
      continue;
    }
    const url = buildSigningUrl(baseUrl, requestId, t.signerId, t.token);

    if (t.channel === "qr") {
      out.push({ ...base, status: "manual", note: "Show the QR on screen; the signer scans it with their phone.", signingUrl: url, qrSvg: await renderQrSvg(url) });
      continue;
    }
    if (t.channel === "link") {
      out.push({ ...base, status: "manual", note: "Give this link to the signer.", signingUrl: url });
      continue;
    }
    const provider = providers.find((p) => p.channel === t.channel);
    if (!provider) {
      out.push({ ...base, status: "pending_provider", note: `No ${t.channel} provider is configured (ES-013): nothing was sent. Deliver the link manually.`, signingUrl: url });
      continue;
    }
    try {
      await provider.send({ to: t.channel === "email" ? t.email : (t.phone as string), name: t.name, url, documentName });
      out.push({ ...base, status: "sent", note: `Sent by ${t.channel}.` });
    } catch {
      out.push({ ...base, status: "error", note: `The ${t.channel} provider failed; deliver the link manually.`, signingUrl: url });
    }
  }
  return out;
}
