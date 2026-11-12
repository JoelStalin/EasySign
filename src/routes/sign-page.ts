import type { FastifyInstance, FastifyReply } from "fastify";

/**
 * Minimal public signing page opened from the link or the QR. The page is static (no secrets): the one-time token is
 * read from the URL fragment, removed from the address bar, and sent only in request bodies. All text from the API is
 * inserted with textContent (no innerHTML), and a strict CSP forbids inline scripts and external resources.
 * The signer must open the document before accepting and signing; the server enforces the same rule.
 */

const CSP = "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' blob:; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const HTML = `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Firmar documento</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:680px;margin:0 auto;padding:16px;color:#111}
.card{border:1px solid #ccd;border-radius:8px;padding:16px;margin:12px 0}.warn{background:#fff7e0;border-color:#e0b000}
button,a.btn{font:inherit;padding:10px 16px;border-radius:6px;border:0;background:#0b5fff;color:#fff;cursor:pointer;text-decoration:none;display:inline-block}
button.secondary,a.btn.secondary{background:#eee;color:#111}button:disabled{opacity:.5}code{word-break:break-all;font-size:13px}
img.doc{max-width:100%;border:1px solid #ccd}pre.doc{white-space:pre-wrap;word-break:break-word;max-height:360px;overflow:auto;background:#f6f7f9;padding:12px;border-radius:6px}
input.code{font:inherit;padding:10px;border:1px solid #767680;border-radius:6px;width:9em;letter-spacing:3px;margin-right:8px}
.err{color:#b00020}.ok{color:#0a6b2d}</style></head>
<body><h1>Firma de documento</h1><div id="app"><p>Cargando…</p></div><script src="/sign/app.js"></script></body></html>`;

const JS = `(function () {
  var app = document.getElementById("app");
  var parts = location.pathname.split("/").filter(Boolean); // sign, requestId, signerId
  var requestId = parts[1], signerId = parts[2];
  var token = decodeURIComponent((location.hash || "").slice(1));
  history.replaceState(null, "", location.pathname); // the token never stays in the address bar or the history
  var state = null;
  var docView = null; // what is shown of the document after opening it

  function el(tag, text, cls) { var e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
  function clear() { while (app.firstChild) app.removeChild(app.firstChild); }
  function url(action) { return "/v1/signature-workflows/" + encodeURIComponent(requestId) + "/signers/" + encodeURIComponent(signerId) + "/" + action; }
  function post(action, extra) {
    return fetch(url(action), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(Object.assign({ token: token }, extra || {})) });
  }
  function api(action, extra) {
    return post(action, extra).then(function (r) { return r.json().then(function (j) { if (!r.ok) { var e = new Error(j.message || j.error || "Error"); e.code = j.error; throw e; } return j; }); });
  }
  function fail(e) { clear(); app.appendChild(el("p", "No se pudo continuar: " + e.message + ". Pida un enlace nuevo a quien le envió el documento.", "err")); }

  function openDocument() {
    return post("document").then(function (r) {
      if (!r.ok) return r.json().then(function (j) { throw new Error(j.message || j.error || "Error"); });
      var type = (r.headers.get("content-type") || "").split(";")[0];
      if (type === "text/plain") return r.text().then(function (t) { return { type: type, text: t }; });
      return r.blob().then(function (b) { return { type: type, blobUrl: URL.createObjectURL(b) }; });
    }).then(function (v) { docView = v; return api("view"); }).then(function (s) { state = s; render(); }).catch(fail);
  }

  var otpSent = false;
  var OTP_TEXT = {
    OTP_INVALID: "El código no es correcto. Revíselo e intente de nuevo.",
    OTP_EXPIRED: "El código venció. Pida otro.",
    OTP_TOO_MANY_ATTEMPTS: "Demasiados intentos. Pida otro código.",
    OTP_NO_CODE: "No hay un código activo. Pida uno nuevo.",
    OTP_RESEND_TOO_SOON: "Espere un minuto antes de pedir otro código.",
    OTP_RESEND_LIMIT: "Se pidieron demasiados códigos. Intente más tarde.",
    OTP_DELIVERY_FAILED: "No se pudo enviar el código. Intente de nuevo en unos minutos.",
    OTP_CHANNEL_NOT_CONFIGURED: "El envío de códigos no está disponible. Avise a quien le envió el documento."
  };
  // The signer proves control of their mailbox with a one-time code before the Sign button appears.
  function otpCard() {
    var box = el("div", undefined, "card");
    box.appendChild(el("h3", "Verifique su correo"));
    box.appendChild(el("p", "Antes de firmar le enviaremos un código de 6 dígitos a " + (state.otpEmailHint || "su correo") + ". Vence en 10 minutos y sirve una sola vez."));
    var msg = el("p", "");
    msg.setAttribute("role", "status");
    function show(e) { msg.className = "err"; msg.textContent = OTP_TEXT[e.code] || e.message; }
    if (otpSent) {
      var input = document.createElement("input");
      input.type = "text"; input.className = "code"; input.maxLength = 6;
      input.setAttribute("inputmode", "numeric"); input.setAttribute("autocomplete", "one-time-code"); input.setAttribute("aria-label", "Código de verificación");
      var ok = el("button", "Verificar");
      ok.onclick = function () {
        var code = input.value.replace(/[^0-9]/g, "");
        if (code.length !== 6) { show({ message: "Escriba los 6 dígitos del código." }); return; }
        ok.disabled = true;
        api("otp/verify", { code: code }).then(function (s) { state = s; render(); }).catch(function (e) { ok.disabled = false; show(e); });
      };
      box.appendChild(input); box.appendChild(ok); box.appendChild(document.createTextNode(" "));
    }
    var send = el("button", otpSent ? "Enviar otro código" : "Enviar código", otpSent ? "secondary" : undefined);
    send.onclick = function () {
      send.disabled = true; msg.className = ""; msg.textContent = "Enviando…";
      api("otp/request").then(function () { otpSent = true; render(); }).catch(function (e) { send.disabled = false; show(e); });
    };
    box.appendChild(send); box.appendChild(msg);
    return box;
  }

  function documentCard() {
    var box = el("div", undefined, "card");
    var meta = state.document;
    box.appendChild(el("h3", "Documento a firmar"));
    box.appendChild(el("p", meta.fileName + " · " + Math.max(1, Math.round(meta.size / 1024)) + " KB"));
    if (docView && docView.type === "text/plain") { box.appendChild(el("pre", docView.text, "doc")); }
    else if (docView && docView.type.indexOf("image/") === 0) { var img = document.createElement("img"); img.className = "doc"; img.alt = "Documento a firmar"; img.src = docView.blobUrl; box.appendChild(img); }
    else if (docView) {
      var a = el("a", "Abrir el documento en otra pestaña", "btn"); a.href = docView.blobUrl; a.target = "_blank"; a.rel = "noopener noreferrer"; box.appendChild(a);
      box.appendChild(document.createTextNode(" "));
      var d = el("a", "Descargar", "btn secondary"); d.href = docView.blobUrl; d.download = meta.fileName; box.appendChild(d);
    }
    if (!docView) {
      var open = el("button", state.you.documentViewed ? "Volver a ver el documento" : "Abrir el documento");
      open.onclick = function () { open.disabled = true; openDocument(); };
      box.appendChild(open);
    }
    return box;
  }

  function render() {
    clear();
    var notice = el("div", undefined, "card warn"); notice.appendChild(el("p", state.notice)); app.appendChild(notice);
    var cfg = state.disclosure && state.disclosure.config;
    if (cfg && cfg.platformName) { app.appendChild(el("p", "Plataforma " + cfg.platformName + ", operada por " + cfg.providerName + " (RNC " + cfg.rnc + ")")); }
    var doc = el("div", undefined, "card");
    doc.appendChild(el("h2", state.documentName));
    doc.appendChild(el("p", "Huella SHA-256 del documento:")); doc.appendChild(el("code", state.documentHash));
    doc.appendChild(el("p", "Firmante " + state.position + " · vence " + new Date(state.expiresAt).toLocaleString("es-DO")));
    app.appendChild(doc);
    var st = state.you.status;
    if (state.status === "completed") { app.appendChild(el("p", "Todos firmaron. Proceso completado.", "ok")); return; }
    if (state.status !== "pending") { app.appendChild(el("p", "Esta solicitud está " + state.status + ".", "err")); return; }
    if (st === "signed") { app.appendChild(el("p", "Usted ya firmó. Gracias.", "ok")); return; }
    if (st === "declined") { app.appendChild(el("p", "Usted rechazó este documento.", "err")); return; }
    var d = state.disclosure;
    var mustOpen = state.document && !state.documentViewed;
    if (state.document) app.appendChild(documentCard());
    else app.appendChild(el("p", "Este documento no está disponible en la plataforma: compare la huella con la del documento que le entregaron.", "err"));
    if (mustOpen) { app.appendChild(el("p", "Debe abrir el documento antes de continuar.")); return; }
    if (st === "viewed") {
      var box = el("div", undefined, "card");
      box.appendChild(el("h3", "Información previa al contrato"));
      box.appendChild(el("p", d ? d.signatureKinds : ""));
      if (d) { Object.keys(d.config).forEach(function (k) { box.appendChild(el("p", k + ": " + d.config[k])); }); }
      var label = el("label"); var cb = document.createElement("input"); cb.type = "checkbox"; label.appendChild(cb);
      label.appendChild(document.createTextNode(" He leído y acepto la información anterior y entiendo que esta firma no tiene el valor de la firma digital."));
      box.appendChild(label);
      var go = el("button", "Aceptar y continuar"); go.disabled = true; cb.onchange = function () { go.disabled = !cb.checked; };
      go.onclick = function () { api("consent", { disclosureHash: d.hash }).then(function (s) { state = s; render(); }).catch(fail); };
      box.appendChild(go); app.appendChild(box);
    } else if (st === "consented" && state.requireOtp && !state.otpVerified) {
      app.appendChild(otpCard());
    } else if (st === "consented") {
      var b2 = el("div", undefined, "card");
      b2.appendChild(el("p", "Al pulsar Firmar confirma que es el documento con la huella mostrada arriba."));
      var sign = el("button", "Firmar"); sign.onclick = function () { api("sign", { documentHash: state.documentHash }).then(function (s) { state = s; render(); }).catch(fail); };
      b2.appendChild(sign);
      b2.appendChild(document.createTextNode(" "));
      var no = el("button", "Rechazar", "secondary"); no.onclick = function () { api("decline", { reason: "Rechazado por el firmante" }).then(function (s) { state = s; render(); }).catch(fail); };
      b2.appendChild(no); app.appendChild(b2);
    }
  }
  if (!requestId || !signerId || token.length < 20) { fail(new Error("enlace incompleto")); return; }
  api("view").then(function (s) { state = s; render(); }).catch(fail);
})();`;

export function registerSignPage(app: FastifyInstance): void {
  const headers = (reply: FastifyReply) =>
    reply.header("content-security-policy", CSP).header("referrer-policy", "no-referrer").header("cache-control", "no-store").header("x-content-type-options", "nosniff");
  app.get("/sign/app.js", async (_req, reply) => headers(reply).type("text/javascript; charset=utf-8").send(JS));
  app.get("/sign/:requestId/:signerId", async (_req, reply) => headers(reply).type("text/html; charset=utf-8").send(HTML));
}
