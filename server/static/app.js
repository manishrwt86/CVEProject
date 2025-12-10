async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) {
    console.error("Request failed", res.status, url);
    alert("Request failed: " + res.status);
    return null;
  }
  return await res.json();
}

async function search(vendor, product) {
  const params = new URLSearchParams();
  if (vendor) params.set("vendor", vendor);
  if (product) params.set("product", product);
  const url =
    "/api/search" + (params.toString() ? "?" + params.toString() : "");
  const data = await fetchJSON(url);
  if (data) renderResults(data);
}

async function recent() {
  const data = await fetchJSON("/api/recent?limit=100");
  if (data) renderResults(data);
}

async function topProducts() {
  const chartsDiv = document.getElementById("pngCharts");
  chartsDiv.style.display = "None";
  const data = await fetchJSON("/api/top-products?limit=20");
  const container = document.getElementById("results");
  if (!data || data.length === 0) {
    container.innerHTML = "<p>No products found.</p>";
    return;
  }
  let html =
    "<h3>Top Products</h3><table><tr><th>Vendor</th><th>Product</th><th>Hits</th></tr>";
  data.forEach((r) => {
    html += `<tr><td>${r.vendor || ""}</td><td>${r.product || ""}</td><td>${
      r.hits
    }</td></tr>`;
  });
  html += "</table>";
  container.innerHTML = html;
}

function renderResults(items) {
  const chartsDiv = document.getElementById("pngCharts");
  chartsDiv.style.display = "None";
  const container = document.getElementById("results");
  if (!items || items.length === 0) {
    container.innerHTML = "<p>No CVEs found.</p>";
    return;
  }
  let html =
    "<table><tr><th>CVE</th><th>Published</th><th>CVSS</th><th>Summary</th></tr>";
  items.forEach((it) => {
    const id = it.id || "";
    const published = it.published || "";
    const cvss = it.cvss || it.cvss_v3_score || "";
    const summary = (it.summary || "").slice(0, 200);
    html += `<tr>
      <td><a href="#" data-cve="${id}" class="cve-link">${id}</a></td>
      <td>${published}</td>
      <td>${cvss}</td>
      <td>${summary}</td>
    </tr>`;
  });
  html += "</table>";
  container.innerHTML = html;

  // Bind click handlers for all CVE links
  document.querySelectorAll(".cve-link").forEach((a) => {
    a.addEventListener("click", async (e) => {
      e.preventDefault();
      const id = e.target.getAttribute("data-cve");
      await showCVE(id);
    });
  });
}

async function showCVE(id) {
  const chartsDiv = document.getElementById("pngCharts");
  chartsDiv.style.display = "None";
  const data = await fetchJSON("/api/cve/" + encodeURIComponent(id));
  if (!data) return;
  const container = document.getElementById("results");
  let html = `<h3>${data.id}</h3>
    <p><strong>Published:</strong> ${data.published} 
    <strong>CVSS:</strong> ${data.cvss_v3_score || ""}</p>
    <p>${data.summary}</p>
    <pre>${JSON.stringify(data.raw, null, 2)}</pre>`;
  container.innerHTML = html;
}

async function showStats() {
  const res = await fetch("/api/stats/summary");
  const data = await res.json();
  const container = document.getElementById("results");
  const chartsDiv = document.getElementById("pngCharts");
  chartsDiv.style.display = "block";

  let html = "";

  // Monthly counts table
  if (data.monthly_counts && data.monthly_counts.length > 0) {
    html +=
      "<h3>Monthly CVE Counts</h3><table><tr><th>Year-Month</th><th>Count</th></tr>";
    data.monthly_counts.forEach((row) => {
      html += `<tr><td>${row.year_month}</td><td>${row.count}</td></tr>`;
    });
    html += "</table>";
  }

  // Severity trend table
  if (data.severity_trend && data.severity_trend.length > 0) {
    html +=
      "<h3>Severity Trend (Month × Bucket)</h3><table><tr><th>Year-Month</th><th>Severity</th><th>Count</th></tr>";
    data.severity_trend.forEach((row) => {
      html += `<tr><td>${row.year_month}</td><td>${row.severity_bucket}</td><td>${row.count}</td></tr>`;
    });
    html += "</table>";
  }

  // Top critical vendors table
  if (data.top_critical_vendors && data.top_critical_vendors.length > 0) {
    html +=
      "<h3>Top Vendors by Critical CVEs (cvss ≥ 9.0)</h3><table><tr><th>Vendor</th><th>Critical CVEs</th></tr>";
    data.top_critical_vendors.forEach((row) => {
      html += `<tr><td>${row.vendor}</td><td>${row.critical_cves}</td></tr>`;
    });
    html += "</table>";
  }

  if (!html) {
    html = "<p>No stats available.</p>";
  }
  container.innerHTML = html;

  // --- build charts using Chart.js ---
  if (data.monthly_counts && data.monthly_counts.length > 0) {
    const labels = data.monthly_counts.map((r) => r.year_month);
    const values = data.monthly_counts.map((r) => r.count);
    const ctx1 = document.getElementById("monthlyChart").getContext("2d");
    if (monthlyChartInstance) monthlyChartInstance.destroy();
    monthlyChartInstance = new Chart(ctx1, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "CVE count",
            data: values,
            fill: false,
            tension: 0.2,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: { display: true },
          title: { display: true, text: "CVE count per month" },
        },
      },
    });
  }

  if (data.severity_trend && data.severity_trend.length > 0) {
    // group by severity bucket
    const bySeverity = {};
    data.severity_trend.forEach((row) => {
      const ym = row.year_month;
      const sev = row.severity_bucket;
      if (!bySeverity[sev]) bySeverity[sev] = {};
      bySeverity[sev][ym] = row.count;
    });

    const allLabels = [
      ...new Set(data.severity_trend.map((row) => row.year_month)),
    ].sort();

    const datasets = Object.keys(bySeverity).map((sev) => {
      const arr = allLabels.map((ym) => bySeverity[sev][ym] || 0);
      return {
        label: sev,
        data: arr,
        fill: false,
        tension: 0.2,
      };
    });

    const ctx2 = document.getElementById("severityChart").getContext("2d");
    if (severityChartInstance) severityChartInstance.destroy();
    severityChartInstance = new Chart(ctx2, {
      type: "line",
      data: {
        labels: allLabels,
        datasets,
      },
      options: {
        responsive: true,
        plugins: {
          legend: { display: true },
          title: { display: true, text: "Severity trend by month" },
        },
      },
    });
  }
}

async function showModelSeverity() {
  // clearCharts();

  const resultsDiv = document.getElementById("results");
  resultsDiv.innerHTML = "Loading model severity analysis...";

  // 1) Summary table & bucket counts from CSV-based API
  const res = await fetch("/api/model/severity-summary?limit=200");
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    resultsDiv.innerHTML =
      "<p>Model severity summary not available. " +
      (err.detail || "Run severity_eval.py first.") +
      "</p>";
    return;
  }
  const data = await res.json();
  const table = data.table || [];
  const cvssCounts = data.cvss_counts || {};
  const modelCounts = data.model_counts || {};

  let html =
    "<h3>Model vs CVSS Severity (sample of CVEs)</h3>" +
    "<table><tr><th>CVE</th><th>CVSS Bucket</th><th>Model Bucket</th><th>Summary</th></tr>";

  table.forEach((row) => {
    html += `<tr>
      <td>${row.id}</td>
      <td>${row.cvss_bucket}</td>
      <td>${row.model_bucket}</td>
      <td>${row.summary}</td>
    </tr>`;
  });
  html += "</table>";

  resultsDiv.innerHTML = html;

  // show charts block
  const chartsDiv = document.getElementById("charts");
  if (chartsDiv) chartsDiv.style.display = "block";

  // 2) Bar chart: distribution of CVSS vs model buckets
  const labels = ["low", "medium", "high", "critical"];
  const cvssVals = labels.map((l) => cvssCounts[l] || 0);
  const modelVals = labels.map((l) => modelCounts[l] || 0);

  const ctxBar = document.getElementById("monthlyChart").getContext("2d");
  if (monthlyChartInstance) monthlyChartInstance.destroy();
  monthlyChartInstance = new Chart(ctxBar, {
    type: "bar",
    data: {
      labels,
      datasets: [
        { label: "CVSS buckets", data: cvssVals },
        { label: "Model buckets", data: modelVals },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        title: { display: true, text: "Distribution: CVSS vs Model severity" },
      },
    },
  });

  // 3) Line chart: model severity trend over time from CSV
  const trendRes = await fetch("/api/model/severity-trend-csv");
  if (trendRes.ok) {
    const trend = await trendRes.json();
    const ctxTrend = document
      .getElementById("modelTrendChart")
      .getContext("2d");
    if (severityChartInstance) severityChartInstance.destroy();
    severityChartInstance = new Chart(ctxTrend, {
      type: "line",
      data: {
        labels: trend.labels,
        datasets: [
          { label: "Low", data: trend.low, tension: 0.2 },
          { label: "Medium", data: trend.medium, tension: 0.2 },
          { label: "High", data: trend.high, tension: 0.2 },
          { label: "Critical", data: trend.critical, tension: 0.2 },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          title: {
            display: true,
            text: "Model-predicted severity trend (from severity_eval.csv)",
          },
        },
      },
    });
  }
}

// function clearCharts() {
//   const chartsDiv = document.getElementById("charts");
//   const pngDiv = document.getElementById("pngCharts");
//   if (chartsDiv) chartsDiv.style.display = "none";
//   if (pngDiv) pngDiv.style.display = "none";
//   if (monthlyChartInstance) {
//     monthlyChartInstance.destroy();
//     monthlyChartInstance = null;
//   }
//   if (severityChartInstance) {
//     severityChartInstance.destroy();
//     severityChartInstance = null;
//   }
// }

function setupUI() {
  document
    .getElementById("modelBtn")
    .addEventListener("click", () => showModelSeverity());

  const searchBtn = document.getElementById("searchBtn");
  const recentBtn = document.getElementById("recentBtn");
  const topBtn = document.getElementById("topBtn");
  searchBtn.addEventListener("click", () => {
    const vendor = document.getElementById("vendorInput").value.trim();
    const product = document.getElementById("productInput").value.trim();
    search(vendor, product);
  });

  recentBtn.addEventListener("click", () => {
    recent();
  });

  topBtn.addEventListener("click", () => {
    topProducts();
  });
  document
    .getElementById("statsBtn")
    .addEventListener("click", () => showStats());

  // Load recent CVEs on page load
  recent();
}

document.addEventListener("DOMContentLoaded", setupUI);
