// sftp admin: enhancements on top of server-rendered pages. Every page works
// without this file; it adds tooltips, the theme choice, menus, the drawer,
// sortable columns, filters, selection, copy buttons, the permission
// presets and local times.
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

  function applyTheme(theme) {
    if (theme === "light" || theme === "dark") {
      document.documentElement.dataset.theme = theme;
    } else {
      delete document.documentElement.dataset.theme;
    }
    document.querySelectorAll("[data-theme-set]").forEach((b) => {
      b.setAttribute("aria-pressed", String(b.dataset.themeSet === (theme || "system")));
    });
  }
  applyTheme(store.get("sftp-theme"));

  // Tooltips: one element, placed beside whatever carries data-tip. A label
  // that is already visible (an expanded sidebar) needs no tooltip.
  const tip = document.createElement("div");
  tip.className = "tooltip";
  tip.setAttribute("role", "tooltip");
  tip.hidden = true;
  let tipFor = null;
  function hideTip() {
    tipFor = null;
    tip.hidden = true;
  }
  function showTip(el) {
    const label = el.querySelector(".nav-text, .user-text");
    if (label && label.offsetParent !== null) { hideTip(); return; }
    if (!tip.isConnected) document.body.appendChild(tip);
    tipFor = el;
    tip.textContent = el.dataset.tip;
    tip.hidden = false;
    const r = el.getBoundingClientRect();
    const t = tip.getBoundingClientRect();
    let top;
    let left;
    if (el.dataset.tipSide === "right") {
      left = r.right + 10;
      top = r.top + r.height / 2 - t.height / 2;
    } else {
      top = r.top - t.height - 8;
      if (top < 6) top = r.bottom + 8;
      left = r.left + r.width / 2 - t.width / 2;
    }
    tip.style.left = `${Math.max(6, Math.min(left, window.innerWidth - t.width - 6))}px`;
    tip.style.top = `${Math.max(6, top)}px`;
  }
  document.addEventListener("pointerover", (e) => {
    const el = e.target.closest("[data-tip]");
    if (el && el !== tipFor) showTip(el);
    else if (!el && tipFor) hideTip();
  });
  document.addEventListener("focusin", (e) => {
    const el = e.target.closest("[data-tip]");
    if (el) showTip(el);
  });
  document.addEventListener("focusout", hideTip);
  document.addEventListener("scroll", hideTip, true);

  function localTimes(root) {
    root.querySelectorAll("time[datetime]").forEach((el) => {
      const when = new Date(el.getAttribute("datetime"));
      if (!Number.isNaN(when.getTime())) el.dataset.tip = (el.dataset.tipPrefix || "") + when.toLocaleString();
    });
  }

  const sets = {
    full: ["list", "download", "upload", "delete", "rename", "mkdir", "attributes", "links"],
    readonly: ["list", "download"],
    uploadonly: ["list", "upload", "rename", "mkdir", "attributes"],
  };
  function syncPerms(form) {
    const preset = form.querySelector('input[name="preset"]:checked');
    if (!preset) return;
    const locked = form.querySelector("fieldset[disabled]") !== null;
    const custom = preset.value === "custom";
    const upload = form.querySelector('[data-perm="upload"]');
    form.querySelectorAll("[data-perm]").forEach((box) => {
      if (!custom && sets[preset.value]) box.checked = sets[preset.value].includes(box.dataset.perm);
      const needsUpload = !["list", "download", "upload"].includes(box.dataset.perm);
      box.disabled = locked || !custom || (needsUpload && upload !== null && !upload.checked);
      if (custom && needsUpload && upload !== null && !upload.checked) box.checked = false;
    });
  }

  function syncPassword(form) {
    const mode = form.querySelector('input[name="password_mode"]:checked');
    if (!mode) return;
    form.querySelectorAll("[data-pw-fields] input").forEach((i) => { i.disabled = mode.value !== "set"; });
  }

  // Sorting: a column's cells sort by data-sort when present, else by text;
  // rows with data-group keep their groups in order, such as folders first.
  function sortKey(td) {
    return td.dataset.sort !== undefined ? td.dataset.sort : td.textContent.trim();
  }
  function sortBy(th) {
    const table = th.closest("table");
    const tbody = table.tBodies[0];
    const idx = Array.prototype.indexOf.call(th.parentElement.children, th);
    const dir = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
    th.parentElement.querySelectorAll("th[aria-sort]").forEach((h) => h.removeAttribute("aria-sort"));
    th.setAttribute("aria-sort", dir);
    const number = th.dataset.type === "number";
    const rows = Array.from(tbody.rows);
    rows.sort((a, b) => {
      const ga = a.dataset.group || "";
      const gb = b.dataset.group || "";
      if (ga !== gb) return ga < gb ? -1 : 1;
      const va = sortKey(a.cells[idx]);
      const vb = sortKey(b.cells[idx]);
      const c = number
        ? (parseFloat(va) || 0) - (parseFloat(vb) || 0)
        : va.localeCompare(vb, undefined, { numeric: true, sensitivity: "base" });
      return dir === "ascending" ? c : -c;
    });
    rows.forEach((r) => tbody.appendChild(r));
  }

  function counted(n, el) {
    const one = (el && el.dataset.one) || "item";
    const many = (el && el.dataset.many) || "items";
    return `${n} ${n === 1 ? one : many}`;
  }

  // Selection: the header box picks every visible row; a row a filter hides
  // is never picked, so a bulk action only touches what is on screen.
  function syncPicks(table) {
    const boxes = table.querySelectorAll("tbody tr:not([hidden]) .pick input");
    let picked = 0;
    table.querySelectorAll("tbody .pick input").forEach((b) => {
      b.closest("tr").classList.toggle("picked", b.checked);
      if (b.checked) picked += 1;
    });
    const all = table.querySelector("thead .pick input");
    if (all) {
      all.checked = picked > 0 && picked === boxes.length;
      all.indeterminate = picked > 0 && picked < boxes.length;
    }
    const card = table.closest(".card");
    const bar = card ? card.querySelector(".bulk-bar") : null;
    if (!bar) return;
    bar.hidden = picked === 0;
    const count = bar.querySelector(".count");
    if (count) count.textContent = `${counted(picked, bar)} selected`;
  }

  // Filters for one table: a search box matches each row's .name, and a
  // control with data-filter-key matches the row's data attribute of that
  // name. Rows without a .name, such as an empty-table note, stay as they are.
  function applyFilters(id) {
    const table = document.getElementById(id);
    if (!table || !table.tBodies[0]) return;
    let q = "";
    const want = [];
    document.querySelectorAll(`[data-filter="${id}"]`).forEach((c) => {
      if (!c.dataset.filterKey) {
        q = c.value.trim().toLowerCase();
        return;
      }
      const pressed = c.matches("select") ? null : c.querySelector('[aria-pressed="true"]');
      const value = c.matches("select") ? c.value : (pressed ? pressed.dataset.value : "");
      if (value) want.push([c.dataset.filterKey, value]);
    });
    let total = 0;
    let shown = 0;
    Array.from(table.tBodies[0].rows).forEach((tr) => {
      const name = tr.querySelector(".name");
      if (name === null) return;
      total += 1;
      const ok = name.textContent.toLowerCase().includes(q) && want.every(([k, v]) => tr.dataset[k] === v);
      tr.hidden = !ok;
      if (ok) {
        shown += 1;
      } else {
        const box = tr.querySelector(".pick input");
        if (box) box.checked = false;
      }
    });
    const empty = document.querySelector(`[data-filter-empty="${id}"]`);
    if (empty) empty.hidden = shown > 0 || total === 0;
    const note = document.querySelector(`[data-filter-count="${id}"]`);
    if (note) note.textContent = shown === total ? counted(total, note) : `${shown} of ${counted(total, note)}`;
    syncPicks(table);
  }

  function closeMenus(except) {
    document.querySelectorAll(".user-menu[open], .dropdown[open]").forEach((d) => {
      if (d !== except) d.open = false;
    });
  }

  // What is typed or chosen in a chip list's Add box becomes a chip with the
  // box's field name, kept until the form is saved; the box empties for the
  // next one, and a chosen option leaves the list.
  function addChip(input) {
    const value = input.value.trim();
    const tpl = document.getElementById(input.dataset.chipInput);
    const holder = input.closest("details");
    if (value === "" || !tpl || !holder) return;
    const option = input.tagName === "SELECT" ? input.selectedOptions[0] : null;
    const chip = tpl.content.firstElementChild.cloneNode(true);
    chip.querySelector(".chip-text").textContent = option ? option.textContent : value;
    const box = chip.querySelector("input");
    box.name = input.name;
    box.value = value;
    box.setAttribute("aria-label", `Keep ${value}`);
    const flag = chip.querySelector("img.flag");
    if (flag && option && option.dataset.flag) {
      flag.src = option.dataset.flag;
      flag.dataset.cc = value;
      flag.dataset.tip = option.textContent;
    }
    holder.parentElement.insertBefore(chip, holder);
    countryNames(chip);
    if (option) option.remove();
    input.value = "";
    holder.open = false;
  }

  function app() {
    return document.querySelector(".app");
  }

  // A country code (data-cc) is named in the viewer's language, from the
  // browser's own country names; without them the code stays.
  const regionNames = (() => {
    try { return new Intl.DisplayNames([navigator.language], { type: "region" }); } catch (e) { return null; }
  })();
  function countryNames(root) {
    if (!regionNames) return;
    root.querySelectorAll("[data-cc]").forEach((el) => {
      let name = "";
      try { name = regionNames.of(el.dataset.cc); } catch (e) { return; }
      if (!name) return;
      if (el.tagName === "IMG") el.alt = name;
      el.dataset.tip = name;
    });
  }

  function init(root) {
    localTimes(root);
    countryNames(root);
    root.querySelectorAll("[data-perms-form]").forEach((form) => {
      syncPerms(form);
      syncPassword(form);
    });
  }

  document.addEventListener("click", (e) => {
    const t = e.target;
    const sort = t.closest(".th-sort");
    if (sort) { sortBy(sort.closest("th")); return; }
    const seg = t.closest("[data-filter-key] button");
    if (seg) {
      const group = seg.closest("[data-filter-key]");
      group.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b === seg)));
      applyFilters(group.dataset.filter);
      return;
    }
    const theme = t.closest("[data-theme-set]");
    if (theme) {
      store.set("sftp-theme", theme.dataset.themeSet);
      applyTheme(theme.dataset.themeSet);
      return;
    }
    if (t.closest("[data-open-nav]")) { app().classList.add("nav-open"); return; }
    if (t.closest("[data-close-nav]")) { app().classList.remove("nav-open"); return; }
    const copy = t.closest("[data-copy]");
    if (copy) {
      if (navigator.clipboard) {
        navigator.clipboard.writeText(copy.dataset.copy).then(() => {
          copy.dataset.tipBefore = copy.dataset.tipBefore || copy.dataset.tip || "";
          copy.dataset.tip = "Copied";
          showTip(copy);
          setTimeout(() => { copy.dataset.tip = copy.dataset.tipBefore; }, 1500);
        }, () => { /* the browser refused the clipboard; the text stays selectable */ });
      }
      return;
    }
    const dismiss = t.closest("[data-dismiss]");
    if (dismiss) {
      const note = dismiss.closest(".toast, .alert, .flash");
      if (note) note.remove();
      hideTip();
      return;
    }
    const reveal = t.closest("[data-reveal]");
    if (reveal) {
      const input = reveal.parentElement.querySelector("input");
      const shown = input.type === "text";
      input.type = shown ? "password" : "text";
      reveal.setAttribute("aria-pressed", String(!shown));
      reveal.dataset.tip = shown ? "Show the password" : "Hide the password";
      reveal.setAttribute("aria-label", reveal.dataset.tip);
      showTip(reveal);
      return;
    }
    const toggle = t.closest("[data-table-toggle]");
    if (toggle) {
      const card = toggle.closest(".card");
      const table = card.querySelector(".chart-table");
      const chart = card.querySelector(".chart");
      const toTable = table.hidden;
      table.hidden = !toTable;
      chart.hidden = toTable;
      toggle.setAttribute("aria-pressed", String(toTable));
      toggle.dataset.tip = toTable ? "Show as a chart" : "Show as a table";
      toggle.setAttribute("aria-label", toggle.dataset.tip);
      showTip(toggle);
      return;
    }
    if (t.closest("[data-clear-picks]")) {
      const table = t.closest(".card").querySelector("table");
      table.querySelectorAll(".pick input").forEach((b) => { b.checked = false; });
      syncPicks(table);
      return;
    }
    closeMenus(t.closest(".user-menu, .dropdown"));
  });

  document.addEventListener("change", (e) => {
    const t = e.target;
    const form = t.closest("[data-perms-form]");
    if (form && (t.name === "preset" || t.dataset.perm)) syncPerms(form);
    if (form && t.name === "password_mode") syncPassword(form);
    if (t.closest(".pick")) {
      const table = t.closest("table");
      if (t.closest("thead")) table.querySelectorAll("tbody tr:not([hidden]) .pick input").forEach((b) => { b.checked = t.checked; });
      syncPicks(table);
    }
    if (t.matches("select[data-chip-input]")) addChip(t);
    const chip = t.closest(".chip-toggle");
    if (chip) {
      chip.dataset.tip = t.checked ? "Remove" : "Keep";
      showTip(chip);
    }
  });

  document.addEventListener("input", (e) => {
    const id = e.target.dataset.filter;
    if (id) applyFilters(id);
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.matches && e.target.matches("[data-chip-input]")) {
      e.preventDefault();
      addChip(e.target);
      return;
    }
    if (e.key !== "Escape") return;
    hideTip();
    closeMenus(null);
    const shell = app();
    if (shell) shell.classList.remove("nav-open");
  });

  // A live view (data-follow) polls only while its switch is on.
  document.addEventListener("htmx:beforeRequest", (e) => {
    if (e.detail.elt && e.detail.elt.matches("[data-follow]")) {
      const follow = document.querySelector("[data-autorefresh]");
      if (follow && !follow.checked) e.preventDefault();
    }
  });

  // A live log (data-after names its rows) asks only for what is newer
  // than the newest row it shows.
  document.addEventListener("htmx:configRequest", (e) => {
    const elt = e.detail.elt;
    if (!elt || !elt.dataset.after) return;
    let newest = 0;
    document.querySelectorAll(`${elt.dataset.after} tr[data-id]`).forEach((tr) => {
      newest = Math.max(newest, Number(tr.dataset.id));
    });
    e.detail.parameters.after = String(newest);
  });

  // New rows replace an empty-table note and obey the filters already set.
  document.addEventListener("htmx:afterSwap", (e) => {
    const target = e.detail.target;
    if (!target || !target.querySelector("tr[data-id]")) return;
    target.querySelectorAll("tr[data-empty]").forEach((tr) => tr.remove());
    const table = target.closest("table");
    if (table && table.id) applyFilters(table.id);
  });

  // A share link's page: the token is after the #, which no request
  // carries; the page posts it to name the file, and the form posts it to
  // download the file.
  async function sharePage() {
    const page = document.querySelector("[data-share-page]");
    if (!page) return;
    const token = window.location.hash.slice(1);
    const sub = page.querySelector("[data-share-sub]");
    const form = page.querySelector("[data-share-form]");
    if (!token) { sub.textContent = "This link has no key. Use the whole link you were sent."; return; }
    form.querySelector('[name="token"]').value = token;
    const body = new URLSearchParams({ login_token: form.querySelector('[name="login_token"]').value, token });
    const res = await fetch("/s/info", {
      method: "POST",
      body,
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    if (!res.ok) { sub.textContent = await res.text(); return; }
    const shown = await res.json();
    page.querySelector("[data-share-title]").textContent = shown.name;
    sub.textContent = `Shared with you until ${shown.ends}.`;
    page.querySelector("[data-share-password]").hidden = !shown.password;
    form.hidden = false;
  }

  document.addEventListener("htmx:afterSettle", (e) => init(e.target));
  document.addEventListener("DOMContentLoaded", sharePage);
  document.addEventListener("DOMContentLoaded", () => init(document));
})();
