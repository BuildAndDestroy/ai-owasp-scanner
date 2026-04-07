/* global Chart */

let chart;

/** @type {Array<object>} */
let techRowsRaw = [];
/** @type {'name'|'version'|'source'|null} */
let sortColumn = null;
/** @type {'asc'|'desc'} */
let sortDirection = "asc";

async function fetchJSON(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) {
    const t = await res.text();
    throw new Error(t || res.statusText);
  }
  return res.json();
}

async function loadReports() {
  const items = await fetchJSON("/api/reports");
  const sel = document.getElementById("reportSelect");
  sel.innerHTML = "";
  for (const row of items) {
    const opt = document.createElement("option");
    opt.value = row.id;
    opt.textContent = `${row.target_url} · ${row.created_at}`;
    sel.appendChild(opt);
  }
  if (items.length && !sel.value) {
    sel.selectedIndex = 0;
  }
  document.getElementById("uploadStatus").textContent =
    items.length === 0 ? "No reports yet. Upload a JSON file." : `${items.length} report(s) loaded.`;
}

function renderSummary(summary) {
  const dl = document.getElementById("summaryDl");
  dl.innerHTML = "";
  const rows = [
    ["Target", summary.target_url],
    ["Pages scanned", String(summary.pages_scanned)],
    ["Payloads used", String(summary.payloads_used)],
    ["Scan end", summary.scan_end_time || "—"],
    ["Duration", summary.total_duration_text || "—"],
    ["Unique technologies", String(summary.unique_technology_count)],
  ];
  for (const [k, v] of rows) {
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    dd.textContent = v;
    dl.appendChild(dt);
    dl.appendChild(dd);
  }
}

function cmpStr(a, b) {
  return String(a || "").localeCompare(String(b || ""), undefined, {
    sensitivity: "base",
    numeric: true,
  });
}

function getSortedTechnologies() {
  if (!sortColumn) {
    return techRowsRaw.slice();
  }
  const rows = techRowsRaw.slice();
  const mult = sortDirection === "asc" ? 1 : -1;
  rows.sort((a, b) => {
    const va =
      sortColumn === "name"
        ? a.name
        : sortColumn === "version"
          ? a.version
          : a.source;
    const vb =
      sortColumn === "name"
        ? b.name
        : sortColumn === "version"
          ? b.version
          : b.source;
    return mult * cmpStr(va, vb);
  });
  return rows;
}

function updateSortHeaderClasses() {
  document.querySelectorAll("#techTable thead th.sortable").forEach((th) => {
    th.classList.remove("sort-asc", "sort-desc");
    const key = th.getAttribute("data-sort-key");
    if (sortColumn && key === sortColumn) {
      th.classList.add(sortDirection === "asc" ? "sort-asc" : "sort-desc");
    }
  });
}

function renderTable(techs) {
  const tbody = document.querySelector("#techTable tbody");
  tbody.innerHTML = "";
  for (const t of techs) {
    const tr = document.createElement("tr");
    const urls = (t.example_urls || []).join("\n");
    tr.innerHTML = `
      <td>${escapeHtml(t.name)}</td>
      <td>${escapeHtml(t.version || "")}</td>
      <td>${escapeHtml(t.source || "")}</td>
      <td>${t.page_count}</td>
      <td><small>${escapeHtml(urls)}</small></td>`;
    tbody.appendChild(tr);
  }
  updateSortHeaderClasses();
}

function wireTableSorting() {
  document.querySelectorAll("#techTable thead th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.getAttribute("data-sort-key");
      if (!key || !["name", "version", "source"].includes(key)) {
        return;
      }
      if (sortColumn === key) {
        sortDirection = sortDirection === "asc" ? "desc" : "asc";
      } else {
        sortColumn = /** @type {'name'|'version'|'source'} */ (key);
        sortDirection = "asc";
      }
      renderTable(getSortedTechnologies());
    });
  });
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderChart(techs) {
  const top = techs.slice(0, 15);
  const labels = top.map((t) => {
    const v = t.version ? ` ${t.version}` : "";
    return `${t.name}${v}`.trim();
  });
  const data = top.map((t) => t.page_count);
  const ctx = document.getElementById("techChart");
  if (chart) {
    chart.destroy();
  }
  chart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "Pages mentioning tech",
          data,
          backgroundColor: "rgba(61, 139, 253, 0.6)",
          borderColor: "rgba(61, 139, 253, 1)",
          borderWidth: 1,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: "#8b98a5", maxRotation: 45, minRotation: 45 } },
        y: { ticks: { color: "#8b98a5" }, beginAtZero: true },
      },
      plugins: {
        legend: { labels: { color: "#e7ecf3" } },
      },
    },
  });
}

async function loadSelectedReport() {
  const sel = document.getElementById("reportSelect");
  const id = sel.value;
  if (!id) {
    document.getElementById("summaryDl").innerHTML = "";
    return;
  }
  const data = await fetchJSON(`/api/reports/${id}/technologies`);
  renderSummary(data.summary);
  techRowsRaw = Array.isArray(data.technologies) ? data.technologies.slice() : [];
  sortColumn = null;
  sortDirection = "asc";
  renderTable(getSortedTechnologies());
  renderChart(data.technologies);
}

document.getElementById("refreshBtn").addEventListener("click", () => {
  loadReports().catch((e) => {
    document.getElementById("uploadStatus").textContent = String(e);
  });
});

document.getElementById("reportSelect").addEventListener("change", () => {
  loadSelectedReport().catch((e) => alert(e));
});

document.getElementById("uploadBtn").addEventListener("click", async () => {
  const input = document.getElementById("fileInput");
  const status = document.getElementById("uploadStatus");
  if (!input.files || !input.files[0]) {
    status.textContent = "Choose a JSON file first.";
    return;
  }
  const text = await input.files[0].text();
  status.textContent = "Uploading…";
  try {
    const res = await fetch("/api/reports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: text,
    });
    if (!res.ok) {
      throw new Error(await res.text());
    }
    status.textContent = "Uploaded.";
    await loadReports();
    document.getElementById("reportSelect").selectedIndex = 0;
    await loadSelectedReport();
  } catch (e) {
    status.textContent = String(e);
  }
});

window.addEventListener("DOMContentLoaded", () => {
  wireTableSorting();
  loadReports()
    .then(() => loadSelectedReport())
    .catch((e) => {
      document.getElementById("uploadStatus").textContent = String(e);
    });
});
