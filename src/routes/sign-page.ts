import type { FastifyInstance } from "fastify";

/**
 * Minimal public signing page opened from the link or the QR. The page is static (no secrets): the one-time token is
 * read from the URL fragment, removed from the address bar, and sent only in request bodies. All text from the API is
 * inserted with textContent (no innerHTML), and a strict CSP forbids inline scripts and external resources.
 */

const CSP = "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const HTML = `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Firmar documento</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:640px;margin:0 auto;padding:16px;color:#111}
.card{border:1px solid #ccd;border-radius:8px;padding:16px;margin:12px 0}.warn{background:#fff7e0;border-color:#e0b000}
button{font:inherit;padding:10px 16px;border-radius:6px;border:0;background:#0b5fff;color:#fff;cursor:pointer}
button.secondary{background:#eee;color:#111}button:disabled{opacity:.5}code{word-break:break-all;font-size:13px}
.err{color:#b00020}.ok{color:#0a6b2d}</style></head>
<body><h1>Firma de documento</h1><div id="app"><p>Cargando…</p></div><script src="/sign/app.js"></script></body></html>`;

const JS = `(function () {
  var app = document.getElementById("app");
  var parts = location.pathname.split("/").filter(Boolean); // sign, requestId, signerId
  var requestId = parts[1], signerId = parts[2];
  var token = decodeURIComponent((location.hash || "").slice(1));
  history.replaceState(null, "", location.pathname); // the token never stays in the address bar or the history
  var state = null;

  function el(tag, text, cls) { var e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
  function clear() { while (app.firstChild) app.removeChild(app.firstChild); }
  function api(action, extra) {
    var body = Object.assign({ token: token }, extra || {});
    return fetch("/v1/signature-workflows/" + encodeURIComponent(requestId) + "/signers/" + encodeURIComponent(signerId) + "/" + action,
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.message || j.error || "Error"); return j; }); });
  }
  function fail(e) { clear(); app.appendChild(el("p", "No se pudo continuar: " + e.message + ". Pida un enlace nuevo a quien le envió el documento.", "err")); }
  function render() {
    clear();
    var notice = el("div", undefined, "card warn"); notice.appendChild(el("p", state.notice)); app.appendChild(notice);
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
    if (st === "viewed") {
      var box = el("div", undefined, "card");
      box.appendChild(el("h3", "Información previa al contrato"));
      box.appendChild(el("p", state.disclosure ? state.disclosure.signatureKinds : ""));
      if (d) { Object.keys(d.config).forEach(function (k) { box.appendChild(el("p", k + ": " + d.config[k])); }); }
      var label = el("label"); var cb = document.createElement("input"); cb.type = "checkbox"; label.appendChild(cb);
      label.appendChild(document.createTextNode(" He leído y acepto la información anterior y entiendo que esta firma no tiene el valor de la firma digital."));
      box.appendChild(label);
      var go = el("button", "Aceptar y continuar"); go.disabled = true; cb.onchange = function () { go.disabled = !cb.checked; };
      go.onclick = function () { api("consent", { disclosureHash: d.hash }).then(function (s) { state = s; render(); }).catch(fail); };
      box.appendChild(go); app.appendChild(box);
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
  const headers = (reply: import("fastify").FastifyReply) =>
    reply.header("content-security-policy", CSP).header("referrer-policy", "no-referrer").header("cache-control", "no-store").header("x-content-type-options", "nosniff");
  app.get("/sign/app.js", async (_req, reply) => headers(reply).type("text/javascript; charset=utf-8").send(JS));
  app.get("/sign/:requestId/:signerId", async (_req, reply) => headers(reply).type("text/html; charset=utf-8").send(HTML));
}
