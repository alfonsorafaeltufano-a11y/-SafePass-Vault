"use strict";

(() => {
  const PBKDF2_ITERATIONS = 250000;
  const VERIFIER_TEXT = "safepass-vault-verifier";
  const REVEAL_MS = 20000;
  const CLIPBOARD_CLEAR_MS = 30000;
  const MASK = "••••••••••";

  const state = {
    meta: null,
    credentials: [],
    categories: [],
    verifier: null,
    sealed: false,
    aesKey: null,
    hmacKey: null,
    filter: "Todas",
    query: "",
    sort: { key: "service", dir: 1 },
    revealed: new Map(),
    pending: null,
  };

  const $ = (sel) => document.querySelector(sel);
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  /* ---------- Utilidades ---------- */
  const hexToBytes = (hex) => new Uint8Array(hex.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
  const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const fromB64 = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
  const today = () => new Date().toISOString().slice(0, 10);

  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const child of [].concat(children)) if (child) node.append(child);
    return node;
  }

  function toast(message, type = "info") {
    const t = el("div", { class: `toast ${type}`, role: "status", text: message });
    $("#toasts").append(t);
    setTimeout(() => t.remove(), 3500);
  }

  /* ---------- Motor criptográfico (Web Crypto API) ---------- */
  async function deriveKeys(password, saltBytes) {
    const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      base,
      512
    );
    const aesKey = await crypto.subtle.importKey("raw", bits.slice(0, 32), "AES-GCM", false, ["encrypt", "decrypt"]);
    const hmacKey = await crypto.subtle.importKey(
      "raw",
      bits.slice(32),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
    return { aesKey, hmacKey };
  }

  async function encryptText(key, text) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text));
    return `${toB64(iv)}.${toB64(ct)}`;
  }

  async function decryptText(key, payload) {
    const [ivB64, ctB64] = payload.split(".");
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(ivB64) }, key, fromB64(ctB64));
    return dec.decode(pt);
  }

  /* ---------- Entropía ---------- */
  function entropyBits(pwd) {
    if (!pwd) return 0;
    let pool = 0;
    if (/[a-z]/.test(pwd)) pool += 26;
    if (/[A-Z]/.test(pwd)) pool += 26;
    if (/[0-9]/.test(pwd)) pool += 10;
    if (/[^A-Za-z0-9]/.test(pwd)) pool += 33;
    return Math.round(pwd.length * Math.log2(pool || 1));
  }

  function strengthOf(bits) {
    if (bits == null) return { label: "Sin evaluar", cls: "unknown", color: "#3f6784", pct: 0 };
    if (bits < 45) return { label: "Débil", cls: "weak", color: "#e2483d", pct: Math.max(8, (bits / 128) * 100) };
    if (bits < 70) return { label: "Media", cls: "medium", color: "#f0a417", pct: (bits / 128) * 100 };
    if (bits < 100) return { label: "Fuerte", cls: "strong", color: "#5cbf3a", pct: (bits / 128) * 100 };
    return { label: "Excelente", cls: "excellent", color: "#1e9be0", pct: Math.min(100, (bits / 128) * 100) };
  }

  /* ---------- Generador ---------- */
  const SETS = {
    upper: "ABCDEFGHJKLMNPQRSTUVWXYZ",
    lower: "abcdefghijkmnopqrstuvwxyz",
    digits: "23456789",
    symbols: "!@#$%^&*()-_=+[]{};:,.?",
  };

  function randomIndex(max) {
    const limit = Math.floor(0xffffffff / max) * max;
    const buf = new Uint32Array(1);
    do crypto.getRandomValues(buf);
    while (buf[0] >= limit);
    return buf[0] % max;
  }

  function generatePassword(length, opts) {
    const active = Object.keys(SETS).filter((k) => opts[k]);
    if (!active.length) return "";
    const all = active.map((k) => SETS[k]).join("");
    const chars = active.map((k) => SETS[k][randomIndex(SETS[k].length)]);
    while (chars.length < length) chars.push(all[randomIndex(all.length)]);
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randomIndex(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join("");
  }

  /* ---------- Carga de datos (JSON) ---------- */
  async function loadVault() {
    try {
      const data = JSON.parse($("#vaultConfig").textContent);
      state.meta = {
        vault_id: data.vault_id,
        version: data.version,
        salt: data.salt,
        file: data.file,
        created_at: data.created_at,
      };
      state.categories = data.categories;
      state.credentials = data.credentials.map((c) => ({ ...c, entropy: entropyBits(c.password_seed) }));
      state.sealed = false;
      fillCategorySelect();
      render();
    } catch (err) {
      toast("No se pudo cargar la configuración de la bóveda", "error");
      $("#fileMeta").textContent = "Error al leer el archivo";
    }
  }

  /* ---------- Llave Maestra ---------- */
  function openUnlock(pending) {
    state.pending = pending || null;
    const isImport = pending && pending.type === "import";
    $("#unlockHint").textContent = isImport
      ? "Introduce la Llave Maestra con la que se cifró este backup para verificar su firma HMAC y descifrarlo."
      : state.sealed
        ? "Introduce tu Llave Maestra para descifrar las credenciales en memoria RAM."
        : "Primer uso: define una Llave Maestra (mínimo 8 caracteres). Con ella se cifrarán todas las credenciales con AES-256-GCM.";
    $("#unlockSubmit").textContent = isImport ? "Importar" : state.sealed ? "Desbloquear" : "Crear y cifrar";
    $("#unlockError").textContent = "";
    $("#masterKey").value = "";
    $("#unlockModal").showModal();
    $("#masterKey").focus();
  }

  async function sealSeedCredentials() {
    for (const c of state.credentials) {
      if (c.password_seed != null) {
        c.password_encrypted = await encryptText(state.aesKey, c.password_seed);
        delete c.password_seed;
      }
    }
    state.verifier = await encryptText(state.aesKey, VERIFIER_TEXT);
    state.sealed = true;
  }

  async function handleUnlock(event) {
    event.preventDefault();
    const pwd = $("#masterKey").value;
    if (pwd.length < 8) {
      $("#unlockError").textContent = "La Llave Maestra debe tener al menos 8 caracteres.";
      return;
    }
    const btn = $("#unlockSubmit");
    btn.disabled = true;
    btn.textContent = "Derivando clave…";
    try {
      const pending = state.pending;
      if (pending && pending.type === "import") {
        await importContainer(pending.container, pwd);
      } else {
        const keys = await deriveKeys(pwd, hexToBytes(state.meta.salt));
        if (state.sealed) {
          await decryptText(keys.aesKey, state.verifier);
          Object.assign(state, keys);
          toast("Bóveda desbloqueada", "success");
        } else {
          Object.assign(state, keys);
          await sealSeedCredentials();
          toast("Bóveda sellada con AES-256-GCM", "success");
        }
      }
      $("#unlockModal").close();
      render();
      if (pending && pending.run) await pending.run();
      state.pending = null;
    } catch (err) {
      $("#unlockError").textContent =
        err && err.message === "HMAC"
          ? "Firma HMAC inválida: el archivo fue alterado o la llave es incorrecta."
          : "Llave Maestra incorrecta.";
    } finally {
      btn.disabled = false;
      btn.textContent = state.sealed ? "Desbloquear" : "Crear y cifrar";
    }
  }

  function requireKey(run) {
    if (state.aesKey) return run();
    openUnlock({ type: "action", run });
  }

  function lockVault() {
    state.aesKey = null;
    state.hmacKey = null;
    for (const { timer } of state.revealed.values()) clearTimeout(timer);
    state.revealed.clear();
    render();
    toast("Bóveda bloqueada. Claves purgadas de la memoria.");
  }

  /* ---------- Acciones de credenciales ---------- */
  async function getPlain(cred) {
    if (cred.password_seed != null) return cred.password_seed;
    return decryptText(state.aesKey, cred.password_encrypted);
  }

  function toggleReveal(cred) {
    if (state.revealed.has(cred.id)) {
      clearTimeout(state.revealed.get(cred.id).timer);
      state.revealed.delete(cred.id);
      render();
      return;
    }
    requireKey(async () => {
      let plain;
      try {
        plain = await getPlain(cred);
      } catch {
        toast("No se pudo descifrar esta contraseña", "error");
        return;
      }
      const timer = setTimeout(() => {
        state.revealed.delete(cred.id);
        render();
      }, REVEAL_MS);
      state.revealed.set(cred.id, { plain, timer });
      render();
    });
  }

  async function copyText(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      toast(`${label} copiado al portapapeles`, "success");
      return true;
    } catch {
      toast("No se pudo acceder al portapapeles", "error");
      return false;
    }
  }

  function copyPassword(cred) {
    requireKey(async () => {
      const plain = await getPlain(cred);
      const ok = await copyText(plain, "Contraseña");
      if (ok) {
        setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), CLIPBOARD_CLEAR_MS);
      }
    });
  }

  function deleteCred(cred) {
    if (!confirm(`¿Eliminar la credencial "${cred.service}"?`)) return;
    state.credentials = state.credentials.filter((c) => c.id !== cred.id);
    state.revealed.delete(cred.id);
    render();
    toast("Credencial eliminada");
  }

  /* ---------- Exportar / Importar ---------- */
  async function exportBackup() {
    requireKey(async () => {
      const payload = JSON.stringify({
        vault_id: state.meta.vault_id,
        created_at: state.meta.created_at,
        categories: state.categories,
        verifier: state.verifier,
        credentials: state.credentials,
      });
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, state.aesKey, enc.encode(payload));
      const header = { format: "SafePass-ENC", version: state.meta.version, salt: state.meta.salt, iv: toB64(iv) };
      const ciphertext = toB64(ct);
      const sig = await crypto.subtle.sign("HMAC", state.hmacKey, enc.encode(`${header.salt}.${header.iv}.${ciphertext}`));
      const container = { ...header, exported_at: new Date().toISOString(), ciphertext, hmac: bytesToHex(new Uint8Array(sig)) };
      const blob = new Blob([JSON.stringify(container, null, 2)], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = el("a", { href: url, download: `backup_${today().replaceAll("-", "")}.enc` });
      document.body.append(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast("Backup cifrado exportado", "success");
    });
  }

  async function importContainer(container, pwd) {
    const keys = await deriveKeys(pwd, hexToBytes(container.salt));
    const valid = await crypto.subtle.verify(
      "HMAC",
      keys.hmacKey,
      hexToBytes(container.hmac),
      enc.encode(`${container.salt}.${container.iv}.${container.ciphertext}`)
    );
    if (!valid) throw new Error("HMAC");
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromB64(container.iv) },
      keys.aesKey,
      fromB64(container.ciphertext)
    );
    const data = JSON.parse(dec.decode(pt));
    state.meta = { ...state.meta, vault_id: data.vault_id, salt: container.salt, created_at: data.created_at };
    state.categories = data.categories || state.categories;
    state.credentials = data.credentials;
    state.verifier = data.verifier;
    state.sealed = true;
    state.revealed.clear();
    Object.assign(state, keys);
    fillCategorySelect();
    toast(`Backup importado: ${data.credentials.length} credenciales`, "success");
  }

  function handleImportFile(event) {
    const file = event.target.files[0];
    event.target.value = "";
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const container = JSON.parse(reader.result);
        if (container.format !== "SafePass-ENC" || !container.ciphertext || !container.hmac) throw new Error();
        openUnlock({ type: "import", container });
      } catch {
        toast("Archivo .enc no válido o corrupto", "error");
      }
    };
    reader.readAsText(file);
  }

  /* ---------- Formulario ---------- */
  function fillCategorySelect() {
    const select = $("#fCat");
    select.replaceChildren(...state.categories.map((c) => el("option", { value: c, text: c })));
  }

  function updateMeter() {
    const bits = entropyBits($("#fPass").value);
    const s = strengthOf($("#fPass").value ? bits : null);
    const bar = $("#meterBar");
    bar.style.width = `${$("#fPass").value ? s.pct : 0}%`;
    bar.style.backgroundColor = s.color;
    $("#meterLabel").textContent = `Entropía: ${bits} bits${$("#fPass").value ? ` · ${s.label}` : ""}`;
  }

  function handleSubmit(event) {
    event.preventDefault();
    const form = event.target;
    const service = form.service.value.trim();
    const username = form.username.value.trim();
    const password = form.password.value;
    const url = form.url.value.trim();
    if (!service || !username || !password) {
      toast("Completa servicio, usuario y contraseña", "error");
      return;
    }
    requireKey(async () => {
      const cred = {
        id: `cred_${Date.now().toString(36)}`,
        service,
        url,
        username,
        password_encrypted: await encryptText(state.aesKey, password),
        category: form.category.value,
        updated_at: today(),
        entropy: entropyBits(password),
      };
      state.credentials.unshift(cred);
      form.reset();
      updateMeter();
      render();
      toast(`"${service}" guardado y cifrado`, "success");
      document.getElementById("boveda").scrollIntoView();
    });
  }

  function toggleVisibility(inputSel, btn) {
    const input = $(inputSel);
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    btn.setAttribute("aria-pressed", String(show));
  }

  /* ---------- Render ---------- */
  function colorFor(text) {
    let h = 0;
    for (const ch of text) h = (h * 31 + ch.charCodeAt(0)) % 360;
    return `linear-gradient(180deg, hsl(${h} 80% 65%), hsl(${h} 75% 42%))`;
  }

  function visibleCredentials() {
    const q = state.query.toLowerCase();
    const { key, dir } = state.sort;
    return state.credentials
      .filter((c) => state.filter === "Todas" || c.category === state.filter)
      .filter((c) => !q || [c.service, c.url, c.username].some((v) => (v || "").toLowerCase().includes(q)))
      .sort((a, b) => {
        const va = a[key] ?? "";
        const vb = b[key] ?? "";
        return (typeof va === "number" ? va - vb : String(va).localeCompare(String(vb), "es")) * dir;
      });
  }

  function iconButton(label, path, onclick, extra = "") {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.innerHTML = path;
    const btn = el("button", { type: "button", class: `icon-btn ${extra}`, "aria-label": label, title: label, onclick });
    btn.append(svg);
    return btn;
  }

  const ICONS = {
    eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
    eyeOff: '<path d="M3 3l18 18"/><path d="M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.1M6.6 6.6C3.8 8.4 2 12 2 12s3.5 7 10 7a9.8 9.8 0 0 0 5.4-1.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
    copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
    trash: '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M6 6l1 14h10l1-14"/>',
  };

  function renderRow(c) {
    const revealed = state.revealed.get(c.id);
    const s = strengthOf(c.entropy);
    return el("tr", {}, [
      el("td", { class: "cell-svc" }, [
        el("div", { class: "svc" }, [
          el("span", { class: "favicon", style: `background:${colorFor(c.service)}`, "aria-hidden": "true", text: c.service.charAt(0).toUpperCase() }),
          el("div", {}, [el("span", { class: "svc-name", text: c.service }), el("span", { class: "svc-url", text: c.url || "—" })]),
        ]),
      ]),
      el("td", { text: c.username }),
      el("td", {}, [
        el("div", { class: "pwd-cell" }, [
          el("span", {
            class: `pwd${revealed ? " revealed" : ""}`,
            text: revealed ? revealed.plain : MASK,
            "aria-label": revealed ? "Contraseña visible" : "Contraseña oculta",
          }),
          iconButton(revealed ? `Ocultar contraseña de ${c.service}` : `Mostrar contraseña de ${c.service}`, revealed ? ICONS.eyeOff : ICONS.eye, () => toggleReveal(c), "reveal-btn"),
        ]),
      ]),
      el("td", {}, [el("span", { class: "chip", text: c.category })]),
      el("td", {}, [el("span", { class: `strength ${s.cls}`, text: c.entropy != null ? `${s.label} · ${c.entropy}b` : s.label })]),
      el("td", { text: c.updated_at }),
      el("td", { class: "cell-actions" }, [
        el("div", { class: "actions" }, [
          iconButton(`Copiar usuario de ${c.service}`, ICONS.user, () => copyText(c.username, "Usuario")),
          iconButton(`Copiar contraseña de ${c.service}`, ICONS.copy, () => copyPassword(c)),
          iconButton(`Eliminar ${c.service}`, ICONS.trash, () => deleteCred(c), "danger"),
        ]),
      ]),
    ]);
  }

  function renderCategories() {
    const counts = state.credentials.reduce((acc, c) => ((acc[c.category] = (acc[c.category] || 0) + 1), acc), {});
    const items = ["Todas", ...state.categories].map((cat) =>
      el("li", {}, [
        el(
          "button",
          {
            type: "button",
            class: "cat-btn",
            "aria-pressed": String(state.filter === cat),
            onclick: () => {
              state.filter = cat;
              render();
            },
          },
          [el("span", { text: cat === "Todas" ? "Todas las contraseñas" : cat }), el("span", { class: "cat-count", text: String(cat === "Todas" ? state.credentials.length : counts[cat] || 0) })]
        ),
      ])
    );
    $("#catList").replaceChildren(...items);
  }

  function renderStats() {
    const groups = { strong: 0, medium: 0, weak: 0 };
    for (const c of state.credentials) {
      const cls = strengthOf(c.entropy).cls;
      if (cls === "weak") groups.weak++;
      else if (cls === "medium") groups.medium++;
      else if (cls === "strong" || cls === "excellent") groups.strong++;
    }
    $("#statTotal").textContent = state.credentials.length;
    $("#statStrong").textContent = groups.strong;
    $("#statMedium").textContent = groups.medium;
    $("#statWeak").textContent = groups.weak;
  }

  function renderStatus() {
  const unlocked = Boolean(state.aesKey);
  $("#statusPill").dataset.state = unlocked ? "unlocked" : "locked";
  $("#statusText").textContent = unlocked ? "Desbloqueada" : "Bloqueada";
  $("#lockBtn").textContent = unlocked ? "Bloquear bóveda" : "Desbloquear bóveda";
  $("#lockBtn").setAttribute("aria-label", unlocked ? "Bloquear bóveda" : "Desbloquear bóveda con Llave Maestra");
  $("#lockDescription").textContent = unlocked
  ? "La bóveda está abierta. Al bloquearla, se purga la llave de memoria y se ocultan las contraseñas."
  : "La bóveda está bloqueada. Desbloquéala con tu Llave Maestra para usar tus credenciales.";
    if (state.meta) {
      $("#filePath").textContent = state.meta.file || "/data/vault_data.enc";
      $("#fileMeta").textContent = `${state.meta.vault_id} · v${state.meta.version} · ${state.sealed ? "AES-256-GCM" : "sin sellar"}`;
    }
    const first = state.credentials.find((c) => c.password_encrypted);
    if (first) $("#heroCipher").textContent = first.password_encrypted;
  }

  function renderSortIndicators() {
    document.querySelectorAll(".sort").forEach((btn) => {
      const active = btn.dataset.sort === state.sort.key;
      if (active) btn.dataset.dir = state.sort.dir === 1 ? "asc" : "desc";
      else delete btn.dataset.dir;
      btn.closest("th").setAttribute("aria-sort", active ? (state.sort.dir === 1 ? "ascending" : "descending") : "none");
    });
  }

  function render() {
    const rows = visibleCredentials();
    $("#credBody").replaceChildren(...rows.map(renderRow));
    $("#emptyState").hidden = rows.length > 0;
    $("#resultCount").textContent = `${rows.length} de ${state.credentials.length} credenciales`;
    renderCategories();
    renderStats();
    renderStatus();
    renderSortIndicators();
  }

  /* ---------- Eventos ---------- */
  function bindEvents() {
    $("#menuToggle").addEventListener("click", (e) => {
      const nav = $("#mainNav");
      const open = nav.classList.toggle("open");
      e.currentTarget.setAttribute("aria-expanded", String(open));
    });
    $("#mainNav").addEventListener("click", (e) => {
      if (e.target.closest("a")) {
        $("#mainNav").classList.remove("open");
        $("#menuToggle").setAttribute("aria-expanded", "false");
      }
    });

    $("#heroCta").addEventListener("click", () => {
      if (!state.aesKey) setTimeout(() => openUnlock(), 450);
    });

    $("#searchInput").addEventListener("input", (e) => {
      state.query = e.target.value.trim();
      render();
    });

    $("#newCredBtn").addEventListener("click", () => {
      document.getElementById("generador").scrollIntoView();
      setTimeout(() => $("#fService").focus(), 400);
    });
    $("#exportBtn").addEventListener("click", exportBackup);
    $("#importInput").addEventListener("change", handleImportFile);
    $("#lockBtn").addEventListener("click", () => {
  if (state.aesKey) lockVault();
  else openUnlock();
  });

    $("#unlockForm").addEventListener("submit", handleUnlock);
    $("#cancelUnlock").addEventListener("click", () => {
      state.pending = null;
      $("#unlockModal").close();
    });
    $("#toggleMaster").addEventListener("click", (e) => toggleVisibility("#masterKey", e.currentTarget));

    $("#credForm").addEventListener("submit", handleSubmit);
    $("#credForm").addEventListener("reset", () => setTimeout(updateMeter, 0));
    $("#fPass").addEventListener("input", updateMeter);
    $("#togglePass").addEventListener("click", (e) => toggleVisibility("#fPass", e.currentTarget));

    $("#gLen").addEventListener("input", (e) => ($("#gLenOut").textContent = e.target.value));
    $("#genBtn").addEventListener("click", () => {
      const pwd = generatePassword(Number($("#gLen").value), {
        upper: $("#gUpper").checked,
        lower: $("#gLower").checked,
        digits: $("#gDigits").checked,
        symbols: $("#gSymbols").checked,
      });
      if (!pwd) {
        toast("Selecciona al menos un conjunto de caracteres", "error");
        return;
      }
      $("#fPass").value = pwd;
      $("#fPass").type = "text";
      $("#togglePass").setAttribute("aria-pressed", "true");
      updateMeter();
    });

    const links = document.querySelectorAll(".main-nav a");
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            links.forEach((a) => a.classList.toggle("active", a.getAttribute("href") === `#${entry.target.id}`));
          }
        });
      },
      { rootMargin: "-45% 0px -50% 0px" }
    );
    document.querySelectorAll("main section[id]").forEach((s) => observer.observe(s));

    window.addEventListener("pagehide", () => {
      state.aesKey = null;
      state.hmacKey = null;
    });
  }

  bindEvents();
  loadVault();
})();
