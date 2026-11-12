import type { DeliveryProvider } from "./delivery.js";

/**
 * Outbound mail (backlog ES-013, email part). A `MailProvider` sends one transactional message; which one is used is
 * chosen by environment (`EASYSIGN_MAIL_PROVIDER=cloudflare|none`). With `none` nothing is sent and the platform keeps
 * its previous behaviour: the signing link is returned to the administrator, who delivers it.
 *
 * The API token is never logged, never put in an error message and never returned to a caller.
 */

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
  html: string;
}

export interface MailSendResult {
  /** `not_sent` is only returned by the no-op provider. */
  status: "sent" | "queued" | "not_sent";
  messageId?: string;
}

export interface MailProvider {
  readonly name: string;
  /** false when the provider does not really send (no-op): callers fall back to manual delivery. */
  readonly enabled: boolean;
  send(message: MailMessage): Promise<MailSendResult>;
}

export class MailError extends Error {
  constructor(
    public readonly code: "CONFIG" | "INVALID_MESSAGE" | "REJECTED" | "BOUNCED" | "UNAVAILABLE" | "TIMEOUT",
    message: string,
    public readonly status?: number
  ) {
    super(message);
    this.name = "MailError";
  }
}

/** Current behaviour kept as a provider: sends nothing, so the link goes back to whoever asked for it. */
export class NoopMailProvider implements MailProvider {
  public readonly name = "none";
  public readonly enabled = false;
  public async send(): Promise<MailSendResult> {
    return { status: "not_sent" };
  }
}

const EMAIL = /^[^\s@<>"',;]+@[^\s@<>"',;]+\.[^\s@<>"',;]+$/;
const oneLine = (s: string, max: number) => s.replace(/[\u0000-\u001f\u007f]+/g, " ").trim().slice(0, max);
const isLocalHost = (h: string) => h === "localhost" || h === "127.0.0.1" || h === "[::1]" || h.endsWith(".localhost");

export interface CloudflareEmailOptions {
  accountId: string;
  apiToken: string;
  from: { address: string; name?: string };
  replyTo?: string;
  /** Default `https://api.cloudflare.com/client/v4`. Must be https unless it points to this machine (tests). */
  baseUrl?: string;
  /** Per attempt. Default 10 s. */
  timeoutMs?: number;
  /** Extra attempts after the first one, only for network errors, timeouts, 429 and 5xx. Default 2, capped at 5. */
  maxRetries?: number;
  /** Base wait between attempts (doubles each time). Default 300 ms. */
  retryDelayMs?: number;
  fetchImpl?: typeof fetch;
}

/**
 * Cloudflare Email Sending, REST API:
 *   POST {baseUrl}/accounts/{account_id}/email/sending/send      Authorization: Bearer <token>
 *   { "from": { "address": "...", "name": "..." }, "to": "...", "subject": "...", "text": "...", "html": "..." }
 * The REST API names the sender key `address`. (`email` is the key of the Workers binding; sending it to the REST API
 * is rejected.) Source: developers.cloudflare.com/email-service/api/send-emails/rest-api/ and
 * .../examples/email-sending/recipients/, read on 2026-11-12.
 */
export class CloudflareEmailProvider implements MailProvider {
  public readonly name = "cloudflare";
  public readonly enabled = true;
  private readonly url: string;
  private readonly apiToken: string;
  private readonly from: { address: string; name?: string };
  private readonly replyTo?: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly retryDelayMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: CloudflareEmailOptions) {
    if (!options.accountId || !/^[A-Za-z0-9_-]{1,64}$/.test(options.accountId)) throw new MailError("CONFIG", "CLOUDFLARE_ACCOUNT_ID is missing or malformed.");
    if (!options.apiToken || /\s/.test(options.apiToken)) throw new MailError("CONFIG", "CLOUDFLARE_EMAIL_API_TOKEN is missing or malformed.");
    if (!EMAIL.test(options.from?.address ?? "")) throw new MailError("CONFIG", "EASYSIGN_MAIL_FROM must be an email address of a domain onboarded in Cloudflare Email Sending.");
    if (options.replyTo && !EMAIL.test(options.replyTo)) throw new MailError("CONFIG", "EASYSIGN_MAIL_REPLY_TO must be an email address.");
    let base: URL;
    try { base = new URL(options.baseUrl ?? "https://api.cloudflare.com/client/v4"); } catch { throw new MailError("CONFIG", "EASYSIGN_MAIL_API_BASE_URL is not a valid URL."); }
    if (base.protocol !== "https:" && !(base.protocol === "http:" && isLocalHost(base.hostname))) {
      throw new MailError("CONFIG", "EASYSIGN_MAIL_API_BASE_URL must use https (the API token travels in a header).");
    }
    this.url = `${base.origin}${base.pathname.replace(/\/+$/, "")}/accounts/${options.accountId}/email/sending/send`;
    this.apiToken = options.apiToken;
    const name = options.from.name ? oneLine(options.from.name, 100) : "";
    this.from = name ? { address: options.from.address, name } : { address: options.from.address };
    this.replyTo = options.replyTo;
    this.timeoutMs = Math.max(1, options.timeoutMs ?? 10_000);
    this.maxRetries = Math.min(5, Math.max(0, options.maxRetries ?? 2));
    this.retryDelayMs = Math.max(0, options.retryDelayMs ?? 300);
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  /** Removes the token from any text that is about to leave this class, whatever its origin. */
  private scrub(text: string): string {
    return text.split(this.apiToken).join("[REDACTED]").slice(0, 300);
  }

  public async send(message: MailMessage): Promise<MailSendResult> {
    if (!EMAIL.test(message.to)) throw new MailError("INVALID_MESSAGE", "The recipient is not a valid email address.");
    const subject = oneLine(message.subject, 200);
    if (!subject || !message.text) throw new MailError("INVALID_MESSAGE", "Subject and text are required.");
    const body = JSON.stringify({
      from: this.from,
      to: message.to,
      subject,
      text: message.text,
      html: message.html,
      ...(this.replyTo ? { reply_to: this.replyTo } : {}),
    });

    let last: MailError = new MailError("UNAVAILABLE", "The mail provider could not be reached.");
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) await new Promise((r) => setTimeout(r, this.retryDelayMs * 2 ** (attempt - 1)));
      const outcome = await this.attempt(body, message.to);
      if (!(outcome instanceof MailError)) return outcome;
      last = outcome;
      if (outcome.code !== "UNAVAILABLE" && outcome.code !== "TIMEOUT") break; // a 4xx will not get better by retrying
    }
    throw last;
  }

  private async attempt(body: string, to: string): Promise<MailSendResult | MailError> {
    let response: Response;
    try {
      response = await this.fetchImpl(this.url, {
        method: "POST",
        headers: { authorization: `Bearer ${this.apiToken}`, "content-type": "application/json", accept: "application/json" },
        body,
        redirect: "error", // never follow a redirect carrying the Authorization header
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      const name = (e as { name?: string } | null)?.name;
      if (name === "TimeoutError" || name === "AbortError") return new MailError("TIMEOUT", `The mail provider did not answer within ${this.timeoutMs} ms.`);
      return new MailError("UNAVAILABLE", "The mail provider could not be reached.");
    }

    let payload: { success?: boolean; errors?: Array<{ code?: number; message?: string }>; result?: { delivered?: string[]; queued?: string[]; permanent_bounces?: string[]; message_id?: string } } = {};
    try { payload = JSON.parse(await response.text()); } catch { /* a non-JSON body is described by its status alone */ }
    const detail = this.scrub((payload.errors ?? []).slice(0, 3).map((x) => `${x.code ?? ""} ${x.message ?? ""}`.trim()).join("; "));

    if (response.status === 429 || response.status >= 500) return new MailError("UNAVAILABLE", `The mail provider answered ${response.status}${detail ? `: ${detail}` : ""}.`, response.status);
    if (!response.ok || payload.success !== true) return new MailError("REJECTED", `The mail provider rejected the message (${response.status})${detail ? `: ${detail}` : ""}.`, response.status);

    const result = payload.result ?? {};
    const has = (list: string[] | undefined) => (list ?? []).some((a) => a.toLowerCase() === to.toLowerCase());
    if (has(result.permanent_bounces) && !has(result.delivered) && !has(result.queued)) return new MailError("BOUNCED", "The recipient address bounced permanently.", response.status);
    return { status: has(result.queued) && !has(result.delivered) ? "queued" : "sent", messageId: result.message_id };
  }
}

/** Builds the provider from the environment. A half-configured `cloudflare` fails at start-up instead of failing silently later. */
export function mailProviderFromEnv(env: Record<string, string | undefined>): MailProvider {
  const kind = (env.EASYSIGN_MAIL_PROVIDER ?? "none").trim().toLowerCase();
  if (kind === "" || kind === "none") return new NoopMailProvider();
  if (kind !== "cloudflare") throw new MailError("CONFIG", "EASYSIGN_MAIL_PROVIDER must be `cloudflare` or `none`.");
  return new CloudflareEmailProvider({
    accountId: env.CLOUDFLARE_ACCOUNT_ID ?? "",
    apiToken: env.CLOUDFLARE_EMAIL_API_TOKEN ?? "",
    from: { address: (env.EASYSIGN_MAIL_FROM ?? "").trim(), name: env.EASYSIGN_MAIL_FROM_NAME },
    replyTo: env.EASYSIGN_MAIL_REPLY_TO?.trim() || undefined,
    baseUrl: env.EASYSIGN_MAIL_API_BASE_URL?.trim() || undefined,
  });
}

// ---- templates (Spanish, transactional: one purpose, no images, no marketing layout) ----

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
const page = (paragraphs: string[]) =>
  `<!doctype html><html lang="es"><body style="font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5;color:#111;margin:0;padding:16px">${paragraphs.map((p) => `<p style="margin:0 0 12px">${p}</p>`).join("")}</body></html>`;

export function signingLinkEmail(input: { to: string; name: string; documentName: string; url: string; platformName: string }): MailMessage {
  const name = oneLine(input.name, 120), doc = oneLine(input.documentName, 200), platform = oneLine(input.platformName, 100);
  const text = [
    `Hola, ${name}:`,
    `Tiene un documento pendiente de firma electrónica: "${doc}".`,
    `Para revisarlo y firmarlo, abra este enlace:`,
    input.url,
    `El enlace es personal y de un solo uso. No lo reenvíe.`,
    `Si no esperaba este documento, ignore este mensaje y avise a quien se lo envió.`,
    `${platform}`,
  ].join("\n\n");
  const html = page([
    `Hola, ${esc(name)}:`,
    `Tiene un documento pendiente de firma electrónica: <strong>${esc(doc)}</strong>.`,
    `Para revisarlo y firmarlo, abra este enlace:<br><a href="${esc(input.url)}">${esc(input.url)}</a>`,
    `El enlace es personal y de un solo uso. No lo reenvíe.`,
    `Si no esperaba este documento, ignore este mensaje y avise a quien se lo envió.`,
    esc(platform),
  ]);
  return { to: input.to, subject: `Documento pendiente de firma: ${doc}`, text, html };
}

/** The code goes in the body only, never in the subject (subjects end up in more logs and notifications than bodies). */
export function otpEmail(input: { to: string; name: string; documentName: string; code: string; minutes: number; platformName: string }): MailMessage {
  const name = oneLine(input.name, 120), doc = oneLine(input.documentName, 200), platform = oneLine(input.platformName, 100);
  const text = [
    `Hola, ${name}:`,
    `Su código de verificación para firmar "${doc}" es:`,
    input.code,
    `Vence en ${input.minutes} minutos y sirve una sola vez. No lo comparta con nadie.`,
    `Si usted no lo pidió, ignore este mensaje: nadie puede firmar sin el código.`,
    `${platform}`,
  ].join("\n\n");
  const html = page([
    `Hola, ${esc(name)}:`,
    `Su código de verificación para firmar <strong>${esc(doc)}</strong> es:`,
    `<span style="font-size:24px;letter-spacing:4px;font-weight:bold">${esc(input.code)}</span>`,
    `Vence en ${input.minutes} minutos y sirve una sola vez. No lo comparta con nadie.`,
    `Si usted no lo pidió, ignore este mensaje: nadie puede firmar sin el código.`,
    esc(platform),
  ]);
  return { to: input.to, subject: `Código de verificación para firmar un documento`, text, html };
}

/** `ana.perez@example.do` -> `a***@example.do`: enough for the signer to recognise the mailbox without showing it on screen. */
export function maskEmail(email: string): string {
  const at = email.lastIndexOf("@");
  return at < 1 ? "***" : `${email[0]}***${email.slice(at)}`;
}

/** Adapts the mail provider to the delivery of signing links. No-op provider -> no delivery provider -> `pending_provider`, as before. */
export function emailDeliveryProviders(mail: MailProvider, platformName: string): DeliveryProvider[] {
  if (!mail.enabled) return [];
  return [{
    channel: "email",
    send: async (m) => { await mail.send(signingLinkEmail({ to: m.to, name: m.name, documentName: m.documentName, url: m.url, platformName })); },
  }];
}

// ---- WhatsApp: interface only ----

/**
 * Messaging (WhatsApp) is NOT implemented: the owner has to choose and contract a provider (WhatsApp Business Platform
 * directly or through a BSP) and get the message templates approved. The token used in earlier experiments has expired.
 * Until then only the no-op exists and the `whatsapp` channel keeps returning the link (`pending_provider`).
 */
export interface MessagingProvider {
  readonly channel: "whatsapp";
  readonly enabled: boolean;
  send(message: { to: string; text: string }): Promise<{ status: "sent" | "not_sent" }>;
}

export class NoopMessagingProvider implements MessagingProvider {
  public readonly channel = "whatsapp" as const;
  public readonly enabled = false;
  public async send(): Promise<{ status: "sent" | "not_sent" }> {
    return { status: "not_sent" };
  }
}
