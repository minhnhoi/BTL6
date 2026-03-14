
// access.js
const API_URL = window.location.origin;

const els = {
  back: document.getElementById("btn-back"),
  refresh: document.getElementById("btn-refresh"),
  load: document.getElementById("btn-load"),
  prev: document.getElementById("btn-prev"),
  next: document.getElementById("btn-next"),
  collection: document.getElementById("collectionSelect"),
  limit: document.getElementById("limitInput"),
  skip: document.getElementById("skipInput"),
  rows: document.getElementById("rows"),
  jsonDetail: document.getElementById("jsonDetail"),
  closeDetail: document.getElementById("btn-close-detail"),
  chatLog: document.getElementById("chatLog"),
  chatText: document.getElementById("chatText"),
  send: document.getElementById("btn-send"),
  toast: document.getElementById("toast"),
};

const ADMIN_LOGIN_PAGE = "index.html";
const ADMIN_RETURN_QUERY = "return=admin";
let sessionChecked = false;

function toast(msg, type = "ok") {
  els.toast.classList.remove("hidden");
  els.toast.style.borderColor = type === "err" ? "#ff003c" : "#00ff41";
  els.toast.style.color = type === "err" ? "#ff003c" : "#00ff41";
  els.toast.textContent = msg;
  setTimeout(() => els.toast.classList.add("hidden"), 2200);
}

function gotoAdminLogin(fromFace = false) {
  const next = window.location.href;
  const params = new URLSearchParams();
  params.set("next", next);
  params.set("return", "admin");
  if (fromFace) params.set("fromFace", "1");
  window.location.href = `${ADMIN_LOGIN_PAGE}?${params.toString()}`;
}

async function ensureAdminSession(force = false) {
  if (sessionChecked && !force) return true;

  const res = await fetch(`${API_URL}/admin/session`, {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
  });

  const json = await res.json().catch(() => ({}));
  if (!res.ok || !json.authenticated) {
    sessionChecked = false;
    toast("Phiên Admin không hợp lệ. Chuyển về đăng nhập...", "err");
    setTimeout(() => gotoAdminLogin(true), 900);
    throw new Error("Admin session required");
  }

  sessionChecked = true;
  return true;
}

async function api(path, options = {}) {
  await ensureAdminSession();

  const headers = {
    ...(options.body ? { "Content-Type": "application/json" } : {}),
    ...(options.headers || {}),
  };

  const res = await fetch(`${API_URL}${path}`, {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
    headers,
  });

  if (res.status === 401 || res.status === 403) {
    sessionChecked = false;
    toast("Phiên Admin đã hết hạn hoặc bị từ chối.", "err");
    setTimeout(() => gotoAdminLogin(true), 900);
    throw new Error(`HTTP ${res.status}`);
  }

  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.success === false) {
    throw new Error(json.message || `HTTP ${res.status}`);
  }

  return json;
}

async function loadCollections() {
  try {
    const json = await api("/admin/mongo/collections", { method: "GET" });
    els.collection.innerHTML = "";
    json.collections.forEach((name) => {
      const opt = document.createElement("option");
      opt.value = name;
      opt.textContent = name;
      els.collection.appendChild(opt);
    });

    const prefer = ["NetworkAgg", "AccessLog"];
    const found = prefer.find((p) => json.collections.includes(p));
    if (found) els.collection.value = found;

    toast("Đã tải danh sách collections.");
  } catch (e) {
    console.error(e);
    toast(e.message, "err");
  }
}

function shortPreview(doc) {
  const clone = { ...doc };
  if (clone.events && Array.isArray(clone.events)) clone.events = `[${clone.events.length} events]`;
  if (clone.paths && typeof clone.paths === "object") clone.paths = "[paths map]";

  const s = JSON.stringify(clone);
  return s.length > 260 ? s.slice(0, 260) + "..." : s;
}

function renderRows(docs, collectionName) {
  els.rows.innerHTML = "";

  if (!docs || docs.length === 0) {
    els.rows.innerHTML =
      '<tr><td colspan="3" style="color:#00cc33">Không có dữ liệu.</td></tr>';
    return;
  }

  docs.forEach((doc) => {
    const tr = document.createElement("tr");

    const tdId = document.createElement("td");
    tdId.textContent = doc._id;

    const tdPrev = document.createElement("td");
    tdPrev.className = "preview";
    tdPrev.textContent = shortPreview(doc);

    const tdAct = document.createElement("td");
    tdAct.className = "row-actions";
    tdAct.style.display = "flex";
    tdAct.style.gap = "8px";

    const pretty = () => JSON.stringify(doc, null, 2);

    const btnView = document.createElement("button");
    btnView.className = "btn btn-sm";
    btnView.innerHTML = '<i class="fa-solid fa-eye"></i>';
    btnView.title = "Xem (mở lớp phủ)";
    btnView.onclick = (ev) => {
      ev.stopPropagation();
      els.jsonDetail.textContent = pretty();
      openOverlay(`${collectionName} • ${doc._id}`, pretty());
    };

    const btnCopy = document.createElement("button");
    btnCopy.className = "btn btn-sm";
    btnCopy.innerHTML = '<i class="fa-solid fa-copy"></i>';
    btnCopy.title = "Copy JSON";
    btnCopy.onclick = async (ev) => {
      ev.stopPropagation();
      await copyToClipboard(pretty());
    };

    const btnDel = document.createElement("button");
    btnDel.className = "btn btn-sm btn-danger";
    btnDel.innerHTML = '<i class="fa-solid fa-trash-can"></i>';
    btnDel.title = "Xóa bản ghi";
    btnDel.onclick = async (ev) => {
      ev.stopPropagation();
      if (!confirm(`Xóa _id=${doc._id} trong ${collectionName}?`)) return;
      try {
        await api(
          `/admin/mongo/${encodeURIComponent(collectionName)}/${encodeURIComponent(
            doc._id
          )}`,
          { method: "DELETE" }
        );
        toast("Đã xóa.");
        await loadData();
      } catch (e) {
        toast(e.message, "err");
      }
    };

    tdAct.appendChild(btnView);
    tdAct.appendChild(btnCopy);
    tdAct.appendChild(btnDel);

    tr.appendChild(tdId);
    tr.appendChild(tdPrev);
    tr.appendChild(tdAct);

    tr.onclick = () => {
      els.jsonDetail.textContent = pretty();
    };

    els.rows.appendChild(tr);
  });
}

async function loadData() {
  const collectionName = els.collection.value;
  const limit = parseInt(els.limit.value || "50", 10);
  const skip = parseInt(els.skip.value || "0", 10);

  els.rows.innerHTML =
    '<tr><td colspan="3" style="color:#00cc33">Đang tải...</td></tr>';

  try {
    const json = await api(
      `/admin/mongo/${encodeURIComponent(
        collectionName
      )}?limit=${limit}&skip=${skip}`,
      { method: "GET" }
    );
    renderRows(json.data, collectionName);
    toast(`Loaded ${collectionName} (${json.data.length} records).`);
  } catch (e) {
    console.error(e);
    els.rows.innerHTML =
      '<tr><td colspan="3" style="color:#ff003c">Lỗi tải dữ liệu.</td></tr>';
    toast(e.message, "err");
  }
}

function formatForDisplay(text) {
  let t = String(text ?? "");
  t = t.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  t = t.replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n");
  if (!t.includes("\n") && t.length > 180) {
    t = t.replace(/([.!?])\s+(?=\S)/g, "$1\n");
  }
  return t.trim();
}

async function copyToClipboard(text) {
  const val = String(text ?? "");
  try {
    await navigator.clipboard.writeText(val);
    toast("Đã copy vào clipboard.");
    return true;
  } catch (_) {
    try {
      const ta = document.createElement("textarea");
      ta.value = val;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      ta.style.top = "-9999px";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      if (ok) toast("Đã copy vào clipboard.");
      return ok;
    } catch (e) {
      toast("Không copy được (trình duyệt chặn).", "err");
      return false;
    }
  }
}

let __overlay = null;

function injectExtraStyles() {
  if (document.getElementById("access-extra-style")) return;

  const style = document.createElement("style");
  style.id = "access-extra-style";
  style.textContent = `
    .bubble-head{display:flex;align-items:center;gap:10px;margin-bottom:6px}
    .bubble-head .role{margin-bottom:0}
    .bubble-actions{margin-left:auto;display:flex;gap:6px}
    .btn-icon{background:transparent;border:1px solid var(--line);color:var(--green);padding:4px 8px;font-family:var(--font);font-size:18px;cursor:pointer;display:flex;align-items:center;gap:6px}
    .btn-icon:hover{background:rgba(0,255,65,.08)}
    .bubble .content{white-space:pre-wrap;word-break:break-word;line-height:1.35}

    .ai-overlay{position:fixed;inset:0;background:rgba(0,0,0,.72);display:flex;align-items:center;justify-content:center;z-index:9999;padding:18px}
    .ai-overlay.hidden{display:none}
    .ai-overlay .card{width:min(960px,96vw);max-height:86vh;overflow:hidden;border:1px solid var(--green);background:#000;box-shadow:0 0 0 1px rgba(0,255,65,.25)}
    .ai-overlay .head{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 12px;border-bottom:1px solid var(--line)}
    .ai-overlay .title{font-size:20px;color:var(--green);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .ai-overlay .body{padding:12px;overflow:auto;max-height:calc(86vh - 56px)}
    .ai-overlay pre{margin:0;white-space:pre-wrap;word-break:break-word;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;font-size:14px;line-height:1.35}
  `;
  document.head.appendChild(style);
}

function ensureOverlay() {
  injectExtraStyles();
  if (__overlay) return __overlay;

  const root = document.createElement("div");
  root.id = "aiOverlay";
  root.className = "ai-overlay hidden";
  root.innerHTML = `
    <div class="card" role="dialog" aria-modal="true">
      <div class="head">
        <div class="title" id="aiOverlayTitle">Xem</div>
        <div style="display:flex;gap:8px;align-items:center">
          <button class="btn-icon" id="aiOverlayCopy" title="Copy"><i class="fa-solid fa-copy"></i></button>
          <button class="btn-icon" id="aiOverlayClose" title="Đóng"><i class="fa-solid fa-xmark"></i></button>
        </div>
      </div>
      <div class="body"><pre id="aiOverlayBody"></pre></div>
    </div>
  `;
  document.body.appendChild(root);

  const titleEl = root.querySelector("#aiOverlayTitle");
  const bodyEl = root.querySelector("#aiOverlayBody");
  let lastText = "";

  const close = () => root.classList.add("hidden");

  root.addEventListener("click", (e) => {
    if (e.target === root) close();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !root.classList.contains("hidden")) close();
  });

  root.querySelector("#aiOverlayClose").onclick = close;
  root.querySelector("#aiOverlayCopy").onclick = () => copyToClipboard(lastText);

  __overlay = {
    open: (title, text) => {
      lastText = String(text ?? "");
      titleEl.textContent = String(title ?? "Xem");
      bodyEl.textContent = lastText;
      root.classList.remove("hidden");
    },
    close,
  };

  return __overlay;
}

function openOverlay(title, text) {
  ensureOverlay().open(title, text);
}

const chatMessages = [
  {
    role: "system",
    content: `Bạn là trợ lý của trang Admin quản lý truy cập. Trả lời NGẮN GỌN nhưng có cấu trúc rõ ràng, dễ đọc.

Yêu cầu định dạng:
- Mỗi ý xuống dòng riêng.
- Ưu tiên gạch đầu dòng (-) và đánh số khi cần.
- Nếu hợp lý: chia mục TÓM TẮT / PHÁT HIỆN / KHUYẾN NGHỊ / CẢNH BÁO / THÔNG TIN THIẾT BỊ TRUY CẬP.
- Tránh viết một đoạn dài liền nhau.`,
  },
];

function addChat(role, content) {
  injectExtraStyles();

  const raw = String(content ?? "");
  const formatted = formatForDisplay(raw);

  const div = document.createElement("div");
  div.className = "bubble" + (role === "user" ? " me" : "");

  const head = document.createElement("div");
  head.className = "bubble-head";

  const roleEl = document.createElement("div");
  roleEl.className = "role";
  roleEl.textContent = String(role || "").toUpperCase();

  const actions = document.createElement("div");
  actions.className = "bubble-actions";

  const btnView = document.createElement("button");
  btnView.className = "btn-icon";
  btnView.innerHTML = '<i class="fa-solid fa-eye"></i>';
  btnView.title = "Xem (mở lớp phủ)";
  btnView.onclick = (ev) => {
    ev.stopPropagation();
    openOverlay(`Chat • ${String(role || "").toUpperCase()}`, formatted);
  };

  const btnCopy = document.createElement("button");
  btnCopy.className = "btn-icon";
  btnCopy.innerHTML = '<i class="fa-solid fa-copy"></i>';
  btnCopy.title = "Copy";
  btnCopy.onclick = async (ev) => {
    ev.stopPropagation();
    await copyToClipboard(raw);
  };

  actions.appendChild(btnView);
  actions.appendChild(btnCopy);

  head.appendChild(roleEl);
  head.appendChild(actions);

  const body = document.createElement("div");
  body.className = "content";
  body.textContent = formatted;

  div.appendChild(head);
  div.appendChild(body);

  els.chatLog.appendChild(div);
  els.chatLog.scrollTop = els.chatLog.scrollHeight;
}

async function sendChat() {
  const text = (els.chatText.value || "").trim();
  if (!text) return;

  els.chatText.value = "";
  chatMessages.push({ role: "user", content: text });
  addChat("user", text);

  els.send.disabled = true;

  try {
    const json = await api("/admin/chatgpt", {
      method: "POST",
      body: JSON.stringify({
        model: "gemini-2.5-flash",
        messages: chatMessages,
        temperature: 0.3,
      }),
    });

    const reply = json.reply || "(empty)";
    chatMessages.push({ role: "assistant", content: reply });
    addChat("assistant", reply);
  } catch (e) {
    console.error(e);
    addChat("assistant", `Lỗi: ${e.message}`);
    toast(e.message, "err");
  } finally {
    els.send.disabled = false;
  }
}

els.back.onclick = () => (window.location.href = "index.html?return=admin");
els.refresh.onclick = async () => {
  await loadCollections();
  await loadData();
};
els.load.onclick = loadData;

els.prev.onclick = () => {
  const skip = Math.max(
    parseInt(els.skip.value || "0", 10) - parseInt(els.limit.value || "50", 10),
    0
  );
  els.skip.value = String(skip);
  loadData();
};
els.next.onclick = () => {
  const skip = Math.max(
    parseInt(els.skip.value || "0", 10) + parseInt(els.limit.value || "50", 10),
    0
  );
  els.skip.value = String(skip);
  loadData();
};

els.closeDetail.onclick = () => {
  els.jsonDetail.textContent = "Chọn một dòng để xem chi tiết...";
};

document.querySelectorAll(".chip").forEach((c) => {
  c.addEventListener("click", () => {
    const name = c.getAttribute("data-collection");
    if (name) {
      els.collection.value = name;
      els.skip.value = "0";
      loadData();
    }
  });
});

els.send.onclick = sendChat;
els.chatText.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendChat();
  }
});

(async function init() {
  injectExtraStyles();
  ensureOverlay();
  await ensureAdminSession(true);
  await loadCollections();
  await loadData();
  addChat(
    "assistant",
    "Xin chào Admin. Mở tab MongoDB để xem log, hoặc hỏi mình về truy cập đáng ngờ."
  );
})();
