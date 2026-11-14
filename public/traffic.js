// IAM Lab · "Tráfico en vivo": anima cada petición real del flujo entre los participantes.
// Sin dependencias ni build: SVG + requestAnimationFrame. Respeta prefers-reduced-motion.

const NODES = [
  { id: "user", name: "Tú", short: "Tú", sub: "navegador" },
  { id: "spa", name: "Lab SPA", short: "SPA", sub: "la aplicación" },
  { id: "as", name: "Servidor de autorización", short: "Autorización", sub: "/as/authorize · /as/token · /as/jwks" },
  { id: "api", name: "API", short: "API", sub: "/as/userinfo" },
];
// Dos geometrías: ancha (escritorio) y compacta (móvil), para que el texto no quede diminuto.
const LAYOUTS = {
  wide: { W: 1000, H: 124, Y: 92, X: { user: 110, spa: 370, as: 630, api: 890 }, nameY: -58, subs: true },
  compact: { W: 520, H: 96, Y: 64, X: { user: 50, spa: 185, as: 335, api: 470 }, nameY: -28, subs: false },
};
const SVG_NS = "http://www.w3.org/2000/svg";
const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
const narrow = window.matchMedia("(max-width: 640px)");

let svg, layer, log, L;
let queue = Promise.resolve();

const el = (name, attrs = {}, parent) => {
  const n = document.createElementNS(SVG_NS, name);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (parent) parent.appendChild(n);
  return n;
};
const ease = (t) => (t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2);

function drawDiagram(container) {
  L = narrow.matches ? LAYOUTS.compact : LAYOUTS.wide;
  const next = el("svg", { viewBox: `0 0 ${L.W} ${L.H}`, class: "flow-svg", role: "img", "aria-label": "Diagrama de las peticiones entre tú, la aplicación, el servidor de autorización y la API" });
  el("line", { x1: L.X.user, x2: L.X.api, y1: L.Y, y2: L.Y, class: "flow-wire" }, next);
  for (const n of NODES) {
    const g = el("g", { class: "flow-node", "data-node": n.id, transform: `translate(${L.X[n.id]} ${L.Y})` }, next);
    el("circle", { r: 16, class: "flow-halo" }, g);
    el("circle", { r: 9, class: "flow-dot" }, g);
    el("text", { y: L.nameY, class: "flow-name" }, g).textContent = L.subs ? n.name : n.short;
    if (L.subs) el("text", { y: -38, class: "flow-sub" }, g).textContent = n.sub;
  }
  layer = el("g", {}, next);
  if (svg) svg.replaceWith(next);
  else container.querySelector(".flow-head").after(next);
  svg = next;
}

export function mountTraffic(container) {
  container.innerHTML = `
    <div class="flow-head">
      <span class="label">Tráfico en vivo</span>
      <span class="flow-legend"><i class="dot req"></i>petición <i class="dot ok"></i>respuesta OK <i class="dot bad"></i>error</span>
    </div>`;
  drawDiagram(container);
  narrow.addEventListener("change", () => drawDiagram(container));
  log = document.createElement("ol");
  log.className = "flow-log";
  log.setAttribute("aria-live", "polite");
  log.innerHTML = `<li class="flow-empty">Aún no ha pasado nada. Cada petición del flujo aparecerá aquí.</li>`;
  container.appendChild(log);
}

function pulse(node, kind) {
  const g = svg && svg.querySelector(`[data-node="${node}"]`);
  if (!g) return;
  g.classList.remove("hit", "ok", "bad", "req");
  void g.getBBox(); // reinicia la animación CSS
  g.classList.add("hit", kind);
  setTimeout(() => g.classList.remove("hit", kind), 900);
}

function addLog(kind, from, to, text, arrow) {
  if (!log) return;
  log.querySelector(".flow-empty")?.remove();
  const li = document.createElement("li");
  li.className = kind;
  const name = (id) => NODES.find((n) => n.id === id).name;
  li.innerHTML = `<span class="arrow"></span><span class="what"></span><span class="who"></span>`;
  li.querySelector(".arrow").textContent = arrow || (kind === "req" ? "→" : "←");
  li.querySelector(".what").textContent = text;
  li.querySelector(".who").textContent = `${name(from)} → ${name(to)}`;
  log.prepend(li);
  while (log.children.length > 8) log.lastChild.remove();
}

// Crea el "paquete": una píldora con el texto de la petición o la respuesta.
function makePacket(kind, text) {
  const g = el("g", { class: `packet ${kind}` }, layer);
  const rect = el("rect", { rx: 13, height: 26, y: -13 }, g);
  const t = el("text", { y: 5 }, g);
  t.textContent = text.length > 34 ? text.slice(0, 33) + "…" : text;
  const w = Math.max(60, t.getComputedTextLength() + 26);
  rect.setAttribute("width", w);
  rect.setAttribute("x", -w / 2);
  return g;
}

async function fly(from, to, kind, text, logText = text, arrow) {
  pulse(from, kind);
  addLog(kind, from, to, logText, arrow);
  if (!svg || reduce.matches) {
    pulse(to, kind);
    return;
  }
  const g = makePacket(kind, text);
  const x0 = L.X[from], x1 = L.X[to];
  const dur = 380 + Math.abs(x1 - x0) * 0.9;
  const start = performance.now();
  await new Promise((resolve) => {
    const frame = (now) => {
      const t = Math.min(1, (now - start) / dur);
      const x = x0 + (x1 - x0) * ease(t);
      const arc = Math.sin(Math.PI * t) * (kind === "req" ? -14 : 14);
      g.setAttribute("transform", `translate(${x} ${L.Y + arc})`);
      g.style.opacity = t < 0.08 ? t / 0.08 : t > 0.92 ? (1 - t) / 0.08 : 1;
      if (t < 1) requestAnimationFrame(frame);
      else resolve();
    };
    requestAnimationFrame(frame);
  });
  g.remove();
  pulse(to, kind);
}

// Mantiene el nodo destino "pensando" mientras la petición real está en curso.
function waiting(node) {
  const g = svg && svg.querySelector(`[data-node="${node}"]`);
  if (!g) return () => {};
  g.classList.add("busy");
  return () => g.classList.remove("busy");
}

const serialize = (fn) => {
  const run = queue.then(fn, fn);
  queue = run.catch(() => {});
  return run;
};

/**
 * Anima una secuencia de saltos sin petición real (redirecciones del navegador).
 * hops: [{ from, to, kind: "req" | "ok" | "bad", text }]
 */
export function animateHops(hops) {
  return serialize(async () => {
    for (const h of hops) await fly(h.from, h.to, h.kind || "req", h.text, h.text, "↪");
  });
}

/**
 * Hace una petición real con fetch y la anima: ida, espera mientras el servidor
 * responde y vuelta coloreada según el código HTTP.
 */
export function tracedFetch({ from = "spa", to, label, describe }, input, init) {
  // La petición sale ya: la animación la acompaña, no la retrasa.
  const t0 = performance.now();
  const request = fetch(input, init).then((res) => ({ res, ms: Math.round(performance.now() - t0) }));
  const method = (init && init.method) || "GET";
  const path = new URL(input, location.href).pathname;
  return serialize(async () => {
    await fly(from, to, "req", label, `${method} ${path}`);
    const done = waiting(to);
    let out;
    try {
      out = await request;
    } catch (e) {
      done();
      await fly(to, from, "bad", "error de red");
      throw e;
    }
    done();
    const { res, ms } = out;
    const extra = describe ? await describe(res.clone()).catch(() => "") : "";
    const kind = res.ok ? "ok" : "bad";
    await fly(to, from, kind, `${res.status}${extra ? " · " + extra : ""}`, `${res.status}${extra ? " " + extra : ""} · ${ms} ms`);
    return res;
  });
}
