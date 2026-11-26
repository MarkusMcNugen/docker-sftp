// sftp files: the file manager on top of the server-rendered page. Every
// file name reaches the page through the server's escaping; this script
// reads names from data attributes and writes them back only as text and
// as form values, never as markup.
(() => {
  "use strict";

  const store = {
    get(key) {
      try { return window.localStorage.getItem(key); } catch (e) { return null; }
    },
    set(key, value) {
      try { window.localStorage.setItem(key, value); } catch (e) { /* storage blocked: the choice lasts this page */ }
    },
  };

  const enc = encodeURIComponent;
  const fm = () => document.querySelector("[data-fm]");
  const token = () => { const root = fm(); return root ? root.dataset.csrf : ""; };
  const folder = () => { const root = fm(); return root ? root.dataset.path : "/"; };
  const join = (dir, name) => (dir === "/" ? `/${name}` : `${dir}/${name}`);
  const parentOf = (path) => { const at = path.lastIndexOf("/"); return at <= 0 ? "/" : path.slice(0, at); };
  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
  const touch = window.matchMedia("(hover: none)").matches;

  let selected = new Set();
  let anchor = null;
  let cursor = null;
  let shown = null;
  let lastFocus = null;

  // The entries of the view on screen, list or grid, in page order.
  function entries() {
    const root = fm();
    if (!root) return [];
    const grid = root.querySelector("[data-fm-grid]");
    const scope = grid && !grid.hidden ? grid : root.querySelector("[data-fm-list]");
    return scope ? Array.from(scope.querySelectorAll("[data-entry]")) : [];
  }
  const entryOf = (path) => entries().find((el) => el.dataset.path === path) || null;
  const described = (el, path) => ({
    path, name: el.dataset.name, kind: el.dataset.kind, preview: el.dataset.preview || "",
    archive: el.dataset.archive === "true", size: el.dataset.size || "",
  });
  function item(path) {
    const el = entryOf(path);
    if (el) return described(el, path);
    return { path, name: path.slice(path.lastIndexOf("/") + 1), kind: "file", preview: "", size: "" };
  }
  function showSize(n) {
    if (n < 1000) return `${n} B`;
    const units = ["kB", "MB", "GB", "TB", "PB"];
    let v = n / 1000;
    let u = 0;
    while (v >= 1000 && u < units.length - 1) { v /= 1000; u += 1; }
    return `${v < 10 ? v.toFixed(1) : v.toFixed(0)} ${units[u]}`;
  }

  function paint() {
    const root = fm();
    if (!root) return;
    root.querySelectorAll("[data-entry]").forEach((el) => {
      const on = selected.has(el.dataset.path);
      el.classList.toggle("selected", on);
      el.setAttribute("aria-selected", String(on));
      const box = el.querySelector(".pick input");
      if (box) box.checked = on;
    });
    const rows = root.querySelectorAll("[data-fm-list] [data-entry]").length;
    const all = root.querySelector("[data-fm-all]");
    if (all) {
      all.checked = selected.size > 0 && selected.size === rows;
      all.indeterminate = selected.size > 0 && selected.size < rows;
    }
    // One item's actions are in the details pane; the bar is for several.
    const bar = root.querySelector("[data-fm-bulk]");
    if (bar) {
      bar.hidden = selected.size < 2;
      bar.querySelector(".count").textContent = `${plural(selected.size, "item")} selected`;
    }
    details();
  }

  // The details pane follows the selection: one item's details, the
  // folder's own with nothing selected, a count for several.
  let detailsTimer = 0;
  function details() {
    const root = fm();
    const pane = document.getElementById("details");
    if (!root || !pane) return;
    clearTimeout(detailsTimer);
    if (selected.size > 1) {
      shown = null;
      const head = document.createElement("h3");
      head.textContent = `${plural(selected.size, "item")} selected`;
      const note = document.createElement("p");
      note.className = "fm-summary";
      note.textContent = "Move, copy or delete them from the bar above the list, or right-click one of them.";
      pane.replaceChildren(head, note);
      return;
    }
    const want = selected.size === 1 ? Array.from(selected)[0] : root.dataset.path;
    if (want === shown) return;
    shown = want;
    detailsTimer = setTimeout(() => {
      if (!window.htmx) return;
      const here = want === root.dataset.path ? "&here=true" : "";
      window.htmx.ajax("GET", `./details?path=${enc(want)}${here}`, { target: pane, swap: "innerHTML" });
    }, 120);
  }

  function choose(el, e) {
    const path = el.dataset.path;
    if (e.shiftKey && anchor !== null) {
      const list = entries();
      const a = list.findIndex((x) => x.dataset.path === anchor);
      const b = list.findIndex((x) => x.dataset.path === path);
      if (!(e.ctrlKey || e.metaKey)) selected = new Set();
      if (a >= 0 && b >= 0) list.slice(Math.min(a, b), Math.max(a, b) + 1).forEach((x) => selected.add(x.dataset.path));
    } else if (e.ctrlKey || e.metaKey) {
      if (selected.has(path)) selected.delete(path); else selected.add(path);
      anchor = path;
    } else {
      selected = new Set([path]);
      anchor = path;
    }
    cursor = path;
    paint();
  }

  // Opens a folder in place, keeping the page's history.
  function navigate(url) {
    if (!window.htmx) { window.location.assign(url); return; }
    // The htmx flag lets htmx's own Back handling load the page again.
    window.htmx.ajax("GET", url, { target: "body", swap: "innerHTML" }).then(() => {
      window.history.pushState({ htmx: true }, "", url);
      window.scrollTo(0, 0);
    });
  }

  function download(path) {
    window.location.assign(`./download?path=${enc(path)}`);
  }

  // A file downloads as it is, a folder or several items as one zip file;
  // a link downloads, or opens, what it points to.
  function fetchItems(items) {
    if (items.length === 1) {
      const it = items[0];
      if (it.kind === "file") download(it.path);
      else if (it.kind === "dir") window.location.assign(`./zip?path=${enc(it.path)}`);
      else window.location.assign(`./open?path=${enc(it.path)}`);
      return;
    }
    if (items.length === 0) return;
    // A plain form post: the archive arrives as a download and the page
    // stays, which a script's request could not do without holding it all.
    const form = document.createElement("form");
    form.method = "post";
    form.action = "./zip";
    form.hidden = true;
    const add = (name, value) => {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = value;
      form.appendChild(input);
    };
    add("csrf", token());
    add("folder", folder());
    items.forEach((it) => add("path", it.path));
    document.body.appendChild(form);
    form.submit();
    form.remove();
  }

  function open(it) {
    if (it.kind === "dir") navigate(`./?path=${enc(it.path)}`);
    else if (it.kind === "link") window.location.assign(`./open?path=${enc(it.path)}`);
    else if (it.archive) showArchive(it);
    else if (it.preview) showPreview(it);
    else download(it.path);
  }

  // An archive's entries, zip or tar, listed by the server without unpacking.
  function showArchive(it) {
    const l = layer("archive");
    if (!l || !window.htmx) { download(it.path); return; }
    l.querySelector("[data-title]").textContent = it.name;
    l.querySelector("[data-sub]").textContent = it.size;
    const body = l.querySelector("[data-archive-body]");
    const wait = document.createElement("p");
    wait.className = "fm-summary";
    wait.textContent = "Reading the archive";
    body.replaceChildren(wait);
    window.htmx.ajax("GET", `./archive?path=${enc(it.path)}`, { target: body, swap: "innerHTML" });
    openModal(l);
  }

  // Refreshes the panes after a change made without a page load.
  function refresh() {
    if (!window.htmx) { window.location.reload(); return; }
    window.htmx.ajax("GET", window.location.pathname + window.location.search, { target: "#fm", select: "#fm", swap: "outerHTML" });
  }

  /* ---------- the context menu ---------- */

  function menu() { return document.getElementById("fm-ctx"); }
  function hideMenu() { const m = menu(); if (m) m.hidden = true; }
  function showMenu(x, y) {
    const m = menu();
    if (!m) return;
    const one = selected.size === 1;
    const it = one ? item(Array.from(selected)[0]) : null;
    m.querySelectorAll("[data-need]").forEach((b) => {
      const need = b.dataset.need;
      b.hidden = (need === "one" && !one)
        || (need === "one-file" && !(it && it.kind === "file"))
        || (need === "one-preview" && !(it && it.preview));
    });
    // In <body>, outside every container, the fixed position is the
    // pointer's place in the viewport.
    if (m.parentElement !== document.body) document.body.appendChild(m);
    m.hidden = false;
    m.style.left = `${Math.max(8, Math.min(x, window.innerWidth - m.offsetWidth - 8))}px`;
    m.style.top = `${Math.max(8, Math.min(y, window.innerHeight - m.offsetHeight - 8))}px`;
    const first = m.querySelector(".menu-item:not([hidden])");
    if (first) first.focus();
  }

  /* ---------- dialogs ---------- */

  const layer = (name) => document.querySelector(`[data-modal="${name}"]`);
  function openModal(l) {
    lastFocus = document.activeElement;
    l.hidden = false;
    const field = l.querySelector("input:not([type=hidden]), button[type=submit], button");
    if (field) field.focus();
  }
  function closeModal() {
    document.querySelectorAll(".modal-layer:not([hidden])").forEach((l) => { l.hidden = true; });
    // A preview stops playing and loading once it is closed.
    if (textAbort) textAbort.abort();
    document.querySelectorAll("[data-preview-body], [data-archive-body]").forEach((b) => b.replaceChildren());
    previewing = null;
    if (lastFocus && lastFocus.isConnected) lastFocus.focus();
  }

  /* ---------- previews ---------- */

  const TEXT_STEP = 256 * 1024;
  let previewing = null;
  let textAbort = null;

  // Text arrives a range at a time and goes in as text, never as markup;
  // more loads as the end comes into view, up to the end of the file.
  function textView(src, note) {
    const box = document.createElement("div");
    box.className = "fm-text";
    const pre = document.createElement("pre");
    const more = document.createElement("button");
    more.type = "button";
    more.className = "btn btn-secondary btn-sm";
    more.textContent = "Show more";
    more.hidden = true;
    box.append(pre, more);
    if (textAbort) textAbort.abort();
    textAbort = new AbortController();
    const signal = textAbort.signal;
    const decoder = new TextDecoder("utf-8");
    let next = 0;
    let loading = false;
    const load = async () => {
      if (loading) return;
      loading = true;
      more.hidden = true;
      note.textContent = "Loading";
      let res;
      try {
        res = await fetch(src, { headers: { Range: `bytes=${next}-${next + TEXT_STEP - 1}` }, credentials: "same-origin", signal });
      } catch (e) {
        if (!signal.aborted) note.textContent = "The preview could not be loaded.";
        loading = false;
        return;
      }
      if (res.status === 401) { window.location.assign("/login"); return; }
      if (res.status === 416 && next === 0) { note.textContent = "This file is empty."; loading = false; return; }
      if (!res.ok) { note.textContent = await res.text(); loading = false; return; }
      const bytes = new Uint8Array(await res.arrayBuffer());
      const range = res.headers.get("Content-Range");
      const whole = range && /\/(\d+)$/.exec(range);
      const total = whole ? Number(whole[1]) : next + bytes.length;
      if (next === 0 && bytes.includes(0)) {
        note.textContent = "This file is not text; download it to open it.";
        loading = false;
        return;
      }
      next += bytes.length;
      const last = res.status === 200 || next >= total || bytes.length === 0;
      pre.append(document.createTextNode(decoder.decode(bytes, { stream: !last })));
      note.textContent = last ? `All of ${showSize(total)}` : `The first ${showSize(next)} of ${showSize(total)}`;
      more.hidden = last;
      loading = false;
    };
    more.addEventListener("click", load);
    // The box scrolls, so the button comes into view only at the end of
    // what has loaded.
    if ("IntersectionObserver" in window) {
      new IntersectionObserver((seen) => { if (seen.some((s) => s.isIntersecting) && !more.hidden) load(); }, { root: box }).observe(more);
    }
    load();
    return box;
  }

  function showPreview(it) {
    const l = layer("preview");
    if (!l || !it || !it.preview) return;
    previewing = it;
    l.querySelector("[data-title]").textContent = it.name;
    l.querySelector("[data-sub]").textContent = it.size;
    l.querySelector("[data-preview-download]").setAttribute("href", `./download?path=${enc(it.path)}`);
    const body = l.querySelector("[data-preview-body]");
    const note = l.querySelector("[data-preview-note]");
    const src = `./preview?path=${enc(it.path)}`;
    if (textAbort) textAbort.abort();
    let shown;
    note.textContent = "";
    if (it.preview === "image") {
      shown = document.createElement("img");
      shown.alt = it.name;
      shown.src = src;
    } else if (it.preview === "pdf") {
      shown = document.createElement("iframe");
      shown.title = it.name;
      shown.src = src;
      note.textContent = "PDFs open in your browser's own viewer.";
    } else if (it.preview === "audio" || it.preview === "video") {
      shown = document.createElement(it.preview);
      shown.controls = true;
      shown.preload = "metadata";
      shown.src = src;
    } else {
      shown = textView(src, note);
    }
    body.replaceChildren(shown);
    if (l.hidden) openModal(l);
  }

  // The file before or after in the list that has a preview.
  function stepPreview(by) {
    if (!previewing) return;
    const list = entries().filter((el) => el.dataset.preview);
    const at = list.findIndex((el) => el.dataset.path === previewing.path);
    const el = list[at + by];
    if (!el) return;
    selected = new Set([el.dataset.path]);
    anchor = el.dataset.path;
    cursor = el.dataset.path;
    paint();
    showPreview(described(el, el.dataset.path));
  }
  const anyModal = () => document.querySelector(".modal-layer:not([hidden])") !== null;

  function setPaths(form, items) {
    form.querySelector("[data-paths]").replaceChildren(...items.map((it) => {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "path";
      input.value = it.path;
      return input;
    }));
  }
  function field(form, name) { return form.querySelector(`[name="${name}"]`); }
  function label(form, title, sub, submit) {
    form.querySelector("[data-title]").textContent = title;
    form.querySelector("[data-sub]").textContent = sub;
    form.querySelector("[data-submit]").textContent = submit;
  }

  function nameDialog(kind, it) {
    const l = layer("name");
    if (!l) return;
    const form = l.querySelector("form");
    const rename = kind === "rename";
    form.setAttribute("action", rename ? "./rename" : "./mkdir");
    label(form, rename ? "Rename" : "New folder", rename ? it.name : `In ${fm().dataset.here}`, rename ? "Rename" : "Make the folder");
    field(form, "path").value = rename ? it.path : folder();
    const name = field(form, "name");
    name.value = rename ? it.name : "";
    openModal(l);
    if (rename) {
      const dot = it.kind === "file" ? it.name.lastIndexOf(".") : -1;
      name.setSelectionRange(0, dot > 0 ? dot : it.name.length);
    }
  }

  function targetDialog(kind, items) {
    const l = layer("target");
    if (!l || items.length === 0) return;
    const form = l.querySelector("form");
    const copy = kind === "copy";
    form.setAttribute("action", copy ? "./copy" : "./move");
    const what = items.length === 1 ? items[0].name : plural(items.length, "item");
    label(form, copy ? `Copy ${what}` : `Move ${what}`, `From ${fm().dataset.here}`, copy ? "Copy" : "Move");
    setPaths(form, items);
    field(form, "to").value = folder();
    openModal(l);
  }

  // A move or copy dropped on a folder goes straight to the server.
  function sendTo(kind, items, to) {
    const l = layer("target");
    if (!l || items.length === 0) return;
    const form = l.querySelector("form");
    form.setAttribute("action", kind === "copy" ? "./copy" : "./move");
    setPaths(form, items);
    field(form, "to").value = to;
    form.requestSubmit();
  }

  function deleteDialog(items) {
    const l = layer("delete");
    if (!l || items.length === 0) return;
    const form = l.querySelector("form");
    const what = items.length === 1 ? items[0].name : plural(items.length, "item");
    const folders = items.some((it) => it.kind === "dir");
    label(form, `Delete ${what}?`, "This cannot be undone.", "Delete");
    form.querySelector("[data-folder-warning]").hidden = !folders;
    setPaths(form, items);
    form.querySelector("[data-names]").replaceChildren(...items.map((it) => {
      const li = document.createElement("li");
      li.textContent = it.kind === "dir" ? `${it.name}/` : it.name;
      return li;
    }));
    openModal(l);
  }

  /* ---------- share links ---------- */

  // The server makes the link and answers its token once; the page puts it
  // after the # of the link it shows, and nowhere else.
  function shareDialog(it) {
    const l = layer("share");
    if (!l || it.kind !== "file") return;
    const form = l.querySelector("form");
    form.reset();
    form.querySelector("[data-title]").textContent = `Share ${it.name}`;
    form.querySelector("[data-sub]").textContent = it.size;
    field(form, "path").value = it.path;
    form.querySelector("[data-share-made]").hidden = true;
    form.querySelector("[data-share-error]").textContent = "";
    form.querySelector("[data-submit]").hidden = false;
    openModal(l);
  }

  document.addEventListener("submit", async (e) => {
    const form = e.target.closest && e.target.closest("[data-share-form]");
    if (!form || !fm()) return;
    e.preventDefault();
    e.stopPropagation();
    const res = await fetch("./share", {
      method: "POST",
      headers: { "X-CSRF-Token": token(), "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(new FormData(form)),
      credentials: "same-origin",
    });
    if (res.status === 401) { window.location.assign("/login"); return; }
    if (!res.ok) { form.querySelector("[data-share-error]").textContent = await res.text(); return; }
    const made = await res.json();
    const link = `${window.location.origin}/s#${made.token}`;
    form.querySelector("[data-share-link]").textContent = link;
    form.querySelector("[data-share-copy]").dataset.copy = link;
    form.querySelector("[data-share-ends]").textContent = `It works for one download, until ${made.expires}.`;
    form.querySelector("[data-share-made]").hidden = false;
    form.querySelector("[data-submit]").hidden = true;
  }, true);

  /* ---------- actions ---------- */

  // A button in the details pane acts on the item shown there; any other
  // action on the selection.
  function targets(el) {
    const own = el && el.closest("[data-fm-for]");
    if (own) return [described(own, own.dataset.fmFor)];
    return Array.from(selected).map(item);
  }

  function run(act, el) {
    const items = targets(el);
    switch (act) {
      case "open": if (items.length === 1) open(items[0]); break;
      case "preview": if (items.length === 1) showPreview(items[0]); break;
      case "share": if (items.length === 1) shareDialog(items[0]); break;
      case "download": fetchItems(items); break;
      case "rename": if (items.length === 1) nameDialog("rename", items[0]); break;
      case "mkdir": nameDialog("mkdir"); break;
      case "move": case "copy": targetDialog(act, items); break;
      case "delete": deleteDialog(items); break;
      case "clear": selected = new Set(); paint(); break;
      case "upload": { const p = document.querySelector("[data-fm-pick]"); if (p) p.click(); break; }
      case "upload-folder": { const p = document.querySelector("[data-fm-pick-folder]"); if (p) p.click(); break; }
      case "hide-uploads": { const t = document.querySelector("[data-fm-uploads]"); if (t) t.hidden = true; break; }
      default: break;
    }
  }

  /* ---------- uploads ---------- */

  const queue = [];
  let busy = false;
  let changed = false;

  function tray() { return document.querySelector("[data-fm-uploads]"); }
  function trayTitle() {
    const t = tray();
    if (!t) return;
    const waiting = queue.filter((j) => j.kind === "file").length;
    t.querySelector("[data-fm-uploads-title]").textContent = busy || waiting ? `Uploading, ${plural(waiting + (busy ? 1 : 0), "file")} to go` : "Uploads";
  }
  function addRow(rel) {
    const tpl = document.getElementById("fm-upload-row");
    const rows = document.querySelector("[data-fm-upload-rows]");
    if (!tpl || !rows) return null;
    const row = tpl.content.firstElementChild.cloneNode(true);
    row.querySelector(".name").textContent = rel;
    row.querySelector(".meta-text").textContent = "Waiting";
    rows.appendChild(row);
    return row;
  }
  function setRow(job, text, percent) {
    if (!job.row) return;
    job.row.querySelector(".meta-text").textContent = text;
    const bar = job.row.querySelector("progress");
    bar.value = percent;
    bar.setAttribute("aria-label", `${job.rel}, ${text}`);
  }

  // Queues files, with each one's path below the folder shown, and the
  // folders to make first, empty ones among them.
  function enqueue(files, dirs) {
    const root = fm();
    if (!root || (files.length === 0 && dirs.length === 0)) return;
    const base = folder();
    const taken = new Set(Array.from(root.querySelectorAll("[data-fm-list] [data-entry]")).map((el) => el.dataset.name));
    const top = (rel) => rel.split("/")[0];
    const clashes = Array.from(new Set([...files.map((f) => top(f.rel)), ...dirs.map(top)])).filter((n) => taken.has(n));
    let keepFiles = files;
    let keepDirs = dirs;
    if (clashes.length > 0) {
      const names = clashes.slice(0, 5).join(", ");
      const more = clashes.length > 5 ? ` and ${clashes.length - 5} more` : "";
      const ask = `Already here: ${names}${more}. Upload anyway? Files of the same name are replaced; a folder keeps what else it holds.`;
      if (!window.confirm(ask)) {
        keepFiles = files.filter((f) => !clashes.includes(top(f.rel)));
        keepDirs = dirs.filter((d) => !clashes.includes(top(d)));
      }
    }
    keepDirs.forEach((d) => queue.push({ kind: "dir", path: join(base, d) }));
    keepFiles.forEach((f) => queue.push({ kind: "file", file: f.file, rel: f.rel, path: join(base, f.rel), parents: f.rel.includes("/"), offset: 0, row: addRow(f.rel) }));
    const t = tray();
    if (t) t.hidden = false;
    pump();
  }

  async function pump() {
    if (busy) return;
    busy = true;
    while (queue.length > 0) {
      trayTitle();
      const job = queue.shift();
      if (job.kind === "dir") await makeDir(job); else await send(job);
    }
    busy = false;
    trayTitle();
    if (changed) { changed = false; refresh(); }
  }

  async function makeDir(job) {
    const res = await fetch("./mkdirs", {
      method: "POST",
      headers: { "X-CSRF-Token": token(), "Content-Type": "application/x-www-form-urlencoded" },
      body: `path=${enc(job.path)}`,
      credentials: "same-origin",
    });
    if (res.status === 401) { window.location.assign("/login"); return; }
    if (res.ok) { changed = true; return; }
    const row = addRow(job.path);
    if (row) row.querySelector(".meta-text").textContent = await res.text();
  }

  function send(job) {
    return new Promise((resolve) => {
      let url = `./upload?path=${enc(job.path)}`;
      if (job.offset > 0) url += `&offset=${job.offset}`;
      if (job.parents) url += "&parents=true";
      const xhr = new XMLHttpRequest();
      xhr.open("PUT", url);
      xhr.setRequestHeader("X-CSRF-Token", token());
      const total = job.file.size;
      xhr.upload.onprogress = (ev) => {
        const done = job.offset + ev.loaded;
        setRow(job, `${total ? Math.floor((done / total) * 100) : 100}%`, total ? (done / total) * 100 : 100);
      };
      xhr.onload = () => {
        if (xhr.status === 401) { window.location.assign("/login"); resolve(); return; }
        if (xhr.status === 200) {
          setRow(job, "Done", 100);
          if (job.row) job.row.classList.add("done");
          changed = true;
        } else {
          stopped(job, xhr.responseText || `The server answered ${xhr.status}.`);
        }
        resolve();
      };
      xhr.onerror = () => { stopped(job, "The connection dropped."); resolve(); };
      xhr.send(job.offset > 0 ? job.file.slice(job.offset) : job.file);
    });
  }

  // An upload that stopped keeps what reached the server; Go on sends the
  // rest from there.
  function stopped(job, why) {
    if (!job.row) return;
    job.row.classList.add("failed");
    job.row.querySelector(".meta-text").textContent = why;
    const resume = job.row.querySelector("[data-fm-resume]");
    resume.hidden = false;
    resume.onclick = async () => {
      resume.hidden = true;
      job.row.classList.remove("failed");
      setRow(job, "Checking", 0);
      const res = await fetch(`./size?path=${enc(job.path)}`, { credentials: "same-origin" });
      const held = res.ok ? Number(await res.text()) : 0;
      job.offset = Number.isFinite(held) && held > 0 && held <= job.file.size ? held : 0;
      queue.push(job);
      const t = tray();
      if (t) t.hidden = false;
      pump();
    };
  }

  // Reads what was dropped: files, and folders with everything in them.
  async function dropped(dt) {
    const files = [];
    const dirs = [];
    const roots = Array.from(dt.items || []).map((i) => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null));
    if (roots.length === 0 || roots.some((r) => r === null)) {
      Array.from(dt.files).forEach((f) => files.push({ file: f, rel: f.name }));
      return { files, dirs };
    }
    const walk = async (entry, prefix) => {
      if (entry.isFile) {
        const file = await new Promise((ok, no) => entry.file(ok, no));
        files.push({ file, rel: prefix + file.name });
        return;
      }
      if (!entry.isDirectory) return;
      const here = prefix + entry.name;
      dirs.push(here);
      const reader = entry.createReader();
      for (;;) {
        const batch = await new Promise((ok, no) => reader.readEntries(ok, no));
        if (batch.length === 0) break;
        for (const child of batch) await walk(child, `${here}/`);
      }
    };
    for (const r of roots) await walk(r, "");
    return { files, dirs };
  }

  /* ---------- events ---------- */

  // In the capture phase, so a click that selects never reaches htmx,
  // which would follow the name's link.
  document.addEventListener("click", (e) => {
    const root = fm();
    if (!root) return;
    const t = e.target;
    const entry = t.closest("[data-entry]");
    if (!entry || !root.contains(entry) || t.closest(".pick, [data-fm-more]")) return;
    const name = t.closest("a.name");
    if (name && touch && !(e.ctrlKey || e.metaKey || e.shiftKey)) return;
    if (name && e.button === 0 && !(e.ctrlKey || e.metaKey || e.shiftKey || e.altKey)) {
      e.preventDefault();
      e.stopPropagation();
    } else if (name) {
      return;
    }
    choose(entry, e);
  }, true);

  document.addEventListener("click", (e) => {
    const t = e.target;
    if (!fm()) return;
    if (t.classList && t.classList.contains("modal-layer")) { closeModal(); return; }
    if (t.closest("[data-fm-close]")) { closeModal(); return; }
    const step = t.closest("[data-preview-step]");
    if (step) { stepPreview(Number(step.dataset.previewStep)); return; }
    const act = t.closest("[data-fm-act]");
    if (act) { hideMenu(); run(act.dataset.fmAct, act); return; }
    const more = t.closest("[data-fm-more]");
    if (more) {
      const entry = more.closest("[data-entry]");
      if (!selected.has(entry.dataset.path)) { selected = new Set([entry.dataset.path]); anchor = entry.dataset.path; }
      cursor = entry.dataset.path;
      paint();
      const r = more.getBoundingClientRect();
      showMenu(r.left, r.bottom + 4);
      return;
    }
    if (!t.closest("#fm-ctx")) hideMenu();
    const view = t.closest("[data-fmview]");
    if (view) setView(view.dataset.fmview);
  });

  document.addEventListener("dblclick", (e) => {
    const entry = e.target.closest("[data-entry]");
    if (!entry || !fm() || e.target.closest(".pick, [data-fm-more]")) return;
    e.preventDefault();
    open(described(entry, entry.dataset.path));
  });

  document.addEventListener("contextmenu", (e) => {
    const entry = e.target.closest("[data-entry]");
    if (!entry || !fm()) return;
    e.preventDefault();
    if (!selected.has(entry.dataset.path)) { selected = new Set([entry.dataset.path]); anchor = entry.dataset.path; }
    cursor = entry.dataset.path;
    paint();
    showMenu(e.clientX, e.clientY);
  });

  document.addEventListener("change", (e) => {
    const root = fm();
    if (!root) return;
    const t = e.target;
    if (t.matches("[data-fm-pick], [data-fm-pick-folder]")) {
      const files = Array.from(t.files).map((f) => ({ file: f, rel: f.webkitRelativePath || f.name }));
      const dirs = new Set();
      files.forEach((f) => {
        const parts = f.rel.split("/").slice(0, -1);
        parts.forEach((_, i) => dirs.add(parts.slice(0, i + 1).join("/")));
      });
      enqueue(files, Array.from(dirs));
      t.value = "";
      return;
    }
    const box = t.closest(".pick input");
    if (!box || !root.contains(box)) return;
    if (box.matches("[data-fm-all]")) {
      selected = box.checked ? new Set(Array.from(root.querySelectorAll("[data-fm-list] [data-entry]")).map((el) => el.dataset.path)) : new Set();
    } else {
      const path = box.closest("[data-entry]").dataset.path;
      if (box.checked) selected.add(path); else selected.delete(path);
      anchor = path;
      cursor = path;
    }
    paint();
  });

  // Grid columns, for arrow keys that move by rows of tiles.
  function columns(list) {
    if (list.length === 0 || !list[0].classList.contains("tile")) return 1;
    const top = list[0].offsetTop;
    const n = list.findIndex((el) => el.offsetTop !== top);
    return n > 0 ? n : list.length;
  }

  document.addEventListener("keydown", (e) => {
    const root = fm();
    if (!root) return;
    if (anyModal()) {
      if (e.key === "Escape") { closeModal(); return; }
      if (previewing && !e.target.closest("input, textarea, select, audio, video")) {
        if (e.key === "ArrowRight" || e.key === "ArrowDown") { e.preventDefault(); stepPreview(1); }
        if (e.key === "ArrowLeft" || e.key === "ArrowUp") { e.preventDefault(); stepPreview(-1); }
        if (e.key === " ") { e.preventDefault(); closeModal(); }
      }
      return;
    }
    const m = menu();
    if (m && !m.hidden) {
      if (e.key === "Escape") { hideMenu(); return; }
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        const items = Array.from(m.querySelectorAll(".menu-item:not([hidden])"));
        const at = items.indexOf(document.activeElement);
        const next = items[(at + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length];
        if (next) next.focus();
        e.preventDefault();
      }
      return;
    }
    if (e.target.closest("input, textarea, select, [contenteditable]")) return;
    const list = entries();
    const at = cursor === null ? -1 : list.findIndex((el) => el.dataset.path === cursor);
    const step = (by) => {
      if (list.length === 0) return;
      const el = list[Math.max(0, Math.min(list.length - 1, at < 0 ? 0 : at + by))];
      if (e.shiftKey) {
        if (anchor === null) anchor = el.dataset.path;
        const a = list.findIndex((x) => x.dataset.path === anchor);
        const b = list.indexOf(el);
        selected = new Set(list.slice(Math.min(a, b), Math.max(a, b) + 1).map((x) => x.dataset.path));
      } else {
        selected = new Set([el.dataset.path]);
        anchor = el.dataset.path;
      }
      cursor = el.dataset.path;
      paint();
      el.scrollIntoView({ block: "nearest" });
    };
    const cols = columns(list);
    switch (e.key) {
      case "ArrowDown": e.preventDefault(); step(cols); break;
      case "ArrowUp": e.preventDefault(); step(-cols); break;
      case "ArrowRight": if (cols > 1) { e.preventDefault(); step(1); } break;
      case "ArrowLeft": if (cols > 1) { e.preventDefault(); step(-1); } break;
      case "Home": e.preventDefault(); step(-list.length); break;
      case "End": e.preventDefault(); step(list.length); break;
      case "Enter": if (cursor !== null) { e.preventDefault(); open(item(cursor)); } break;
      case " ": if (cursor !== null) { e.preventDefault(); showPreview(item(cursor)); } break;
      case "Delete": if (selected.size > 0) { e.preventDefault(); run("delete"); } break;
      case "F2": if (selected.size === 1) { e.preventDefault(); run("rename"); } break;
      case "Escape": selected = new Set(); paint(); break;
      case "Backspace": if (folder() !== "/") { e.preventDefault(); navigate(`./?path=${enc(parentOf(folder()))}`); } break;
      case "a": case "A":
        if (e.ctrlKey || e.metaKey) {
          e.preventDefault();
          selected = new Set(list.map((el) => el.dataset.path));
          paint();
        }
        break;
      default: break;
    }
  });

  /* ---------- dragging: entries onto folders, files from the desktop ---------- */

  let dragging = null;
  const dropTarget = (t) => t.closest("[data-entry][data-kind='dir'], .tree-item[data-dir]");
  const dropPath = (el) => el.dataset.path || el.dataset.dir;
  function unmark() { document.querySelectorAll(".drop-target").forEach((el) => el.classList.remove("drop-target")); }

  document.addEventListener("dragstart", (e) => {
    const entry = e.target.closest && e.target.closest("[data-entry]");
    if (!entry || !fm()) return;
    if (!selected.has(entry.dataset.path)) { selected = new Set([entry.dataset.path]); anchor = entry.dataset.path; paint(); }
    dragging = Array.from(selected);
    e.dataTransfer.effectAllowed = "copyMove";
    e.dataTransfer.setData("text/plain", dragging.join("\n"));
  });
  document.addEventListener("dragend", () => { dragging = null; unmark(); });

  document.addEventListener("dragover", (e) => {
    const root = fm();
    if (!root) return;
    if (dragging) {
      const el = dropTarget(e.target);
      unmark();
      if (!el) return;
      const to = dropPath(el);
      if (dragging.includes(to) || dragging.some((p) => to.startsWith(`${p}/`))) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = e.ctrlKey ? "copy" : "move";
      el.classList.add("drop-target");
      return;
    }
    const host = e.target.closest(".drop-host");
    if (host && e.dataTransfer && Array.from(e.dataTransfer.types).includes("Files")) {
      e.preventDefault();
      host.classList.add("dragging");
    }
  });

  document.addEventListener("dragleave", (e) => {
    const host = e.target.closest && e.target.closest(".drop-host");
    if (host && !host.contains(e.relatedTarget)) host.classList.remove("dragging");
  });

  document.addEventListener("drop", async (e) => {
    const root = fm();
    if (!root) return;
    if (dragging) {
      const el = dropTarget(e.target);
      const paths = dragging;
      dragging = null;
      unmark();
      if (!el) return;
      e.preventDefault();
      sendTo(e.ctrlKey ? "copy" : "move", paths.map(item), dropPath(el));
      return;
    }
    const host = e.target.closest(".drop-host");
    if (!host || !e.dataTransfer || !Array.from(e.dataTransfer.types).includes("Files")) return;
    e.preventDefault();
    host.classList.remove("dragging");
    const { files, dirs } = await dropped(e.dataTransfer);
    enqueue(files, dirs);
  });

  /* ---------- the view ---------- */

  function setView(view) {
    const root = fm();
    if (!root) return;
    const grid = view === "grid";
    root.querySelector("[data-fm-list]").hidden = grid;
    root.querySelector("[data-fm-grid]").hidden = !grid;
    root.querySelectorAll("[data-fmview]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.fmview === view)));
    store.set("sftp-files-view", view);
  }

  function init() {
    const root = fm();
    if (!root) return;
    selected = new Set();
    anchor = null;
    cursor = null;
    shown = root.dataset.path;
    setView(store.get("sftp-files-view") === "grid" ? "grid" : "list");
    paint();
  }

  // A page or a refreshed listing starts with nothing selected; the details
  // pane swapping in leaves the selection as it is.
  document.addEventListener("htmx:afterSettle", (e) => {
    const target = e.detail && e.detail.target;
    if (target && target.id === "details") return;
    if (target && (target === document.body || target.id === "fm" || target.querySelector("[data-fm]"))) init();
  });
  document.addEventListener("DOMContentLoaded", init);
})();
