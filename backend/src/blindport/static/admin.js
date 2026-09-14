(function () {
  "use strict";

  const rows = Array.from(document.querySelectorAll("[data-admin-row]"));
  const search = document.querySelector("#adminSearch");
  const status = document.querySelector("#adminStatusFilter");
  const product = document.querySelector("#adminProductFilter");
  const activity = document.querySelector("#adminActivityFilter");
  const connection = document.querySelector("#adminConnectionFilter");
  const clearButton = document.querySelector("#clearAdminFilters");
  const visibleCount = document.querySelector("#adminVisibleCount");
  const noResults = document.querySelector("#adminNoResults");

  function setChartValue(selector, property, attribute) {
    document.querySelectorAll(selector).forEach((element) => {
      const value = Math.max(0, Math.min(100, Number(element.dataset[attribute]) || 0));
      element.style.setProperty(property, `${value}%`);
    });
  }

  setChartValue("[data-segment-size]", "--segment-size", "segmentSize");
  setChartValue("[data-bar-size]", "--bar-size", "barSize");
  setChartValue("[data-bar-height]", "--bar-height", "barHeight");

  if (!search || !status || !product || !activity || !connection || !clearButton || !visibleCount || !noResults) {
    return;
  }

  function matchesStatus(row, value) {
    if (!value) return true;
    if (value === "suspended") return row.dataset.suspended === "true";
    return row.dataset.status === value && row.dataset.suspended !== "true";
  }

  function applyFilters() {
    const query = search.value.trim().toLowerCase();
    let count = 0;
    rows.forEach((row) => {
      const visible =
        (!query || row.textContent.toLowerCase().includes(query)) &&
        matchesStatus(row, status.value) &&
        (!product.value || row.dataset.product === product.value) &&
        (!activity.value || row.dataset.activity === activity.value) &&
        (!connection.value || row.dataset.connection === connection.value);
      row.hidden = !visible;
      if (visible) count += 1;
    });
    visibleCount.textContent = String(count);
    noResults.hidden = count !== 0;
  }

  [search, status, product, activity, connection].forEach((control) => {
    control.addEventListener(control === search ? "input" : "change", applyFilters);
  });
  clearButton.addEventListener("click", () => {
    search.value = "";
    status.value = "";
    product.value = "";
    activity.value = "";
    connection.value = "";
    applyFilters();
    search.focus();
  });
})();
