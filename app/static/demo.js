"use strict";

const resultFilter = document.getElementById("demo-result");
resultFilter.addEventListener("change", () => {
    document.querySelectorAll("tr[data-result]").forEach((row) => {
        row.hidden = resultFilter.value !== "all" && row.dataset.result !== resultFilter.value;
    });
});
