// Mutandae dashboard behaviours: inventory filtering, mobile navigation, and
// the audit trail modal. Written against the standard DOM only — no framework
// and no inline handlers — so the page stays CSP-safe. Listeners are attached
// to long-lived elements or delegated on document, which keeps them working
// after HTMX swaps the inventory or the modal content.
(function () {
  "use strict";

  // --- Inventory filtering (search box + status buttons) ---
  var searchBox = document.querySelector(".search-box input");
  var filterGroup = document.querySelector(".filter-group");
  var currentFilter = "";
  var currentStatus = "all";

  function rowMatches(row) {
    var search = row.getAttribute("data-search") || "";
    var urgency = row.getAttribute("data-urgency") || "";
    var textOK = !currentFilter || search.indexOf(currentFilter) !== -1;
    var statusOK =
      currentStatus === "all" ||
      (currentStatus === "attention"
        ? urgency === "expiring" || urgency === "overdue"
        : urgency === currentStatus);
    return textOK && statusOK;
  }

  // filterRows applies the active search text and status filter to every
  // inventory row. It re-reads the rows each time, so it stays correct after
  // HTMX replaces the table, and it surfaces the client-side empty row when
  // the active filters hide everything.
  function filterRows() {
    var rows = document.querySelectorAll("#identity-list tbody tr[data-search]");
    var visible = 0;
    for (var i = 0; i < rows.length; i++) {
      rows[i].hidden = !rowMatches(rows[i]);
      if (!rows[i].hidden) {
        visible++;
      }
    }
    var emptyRow = document.querySelector("#identity-list tbody tr.empty-row");
    if (emptyRow !== null) {
      emptyRow.hidden = visible > 0;
    }
  }

  if (searchBox) {
    searchBox.addEventListener("input", function () {
      currentFilter = searchBox.value.trim().toLowerCase();
      filterRows();
    });
  }

  if (filterGroup) {
    filterGroup.addEventListener("click", function (event) {
      var button = event.target.closest("button[data-status]");
      if (!button) {
        return;
      }
      currentStatus = button.getAttribute("data-status");
      var buttons = filterGroup.querySelectorAll("button[data-status]");
      for (var i = 0; i < buttons.length; i++) {
        buttons[i].classList.toggle("selected", buttons[i] === button);
      }
      filterRows();
    });
  }

  // --- Mobile navigation toggle ---
  var menuButton = document.querySelector(".menu-button");
  var topnav = document.querySelector(".topnav");
  if (menuButton && topnav) {
    menuButton.addEventListener("click", function () {
      var open = topnav.classList.toggle("is-open");
      menuButton.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  // --- Audit trail modal ---
  var backdrop = document.getElementById("audit-modal");
  var content = document.getElementById("audit-modal-content");
  var lastFocused = null;

  function modalIsOpen() {
    return backdrop !== null && !backdrop.hidden;
  }

  function openModal() {
    if (backdrop === null || content === null) {
      return;
    }
    lastFocused = document.activeElement;
    backdrop.hidden = false;
    document.body.classList.add("modal-open");
    var closeButton = backdrop.querySelector(".modal-close");
    if (closeButton !== null) {
      closeButton.focus();
    }
  }

  function closeModal() {
    if (backdrop === null || backdrop.hidden) {
      return;
    }
    backdrop.hidden = true;
    document.body.classList.remove("modal-open");
    content.innerHTML = "";
    if (lastFocused !== null && typeof lastFocused.focus === "function") {
      lastFocused.focus();
    }
    lastFocused = null;
  }

  // Close on the close button or on a click on the backdrop itself (never on
  // its child dialog). Delegated on document so it survives HTMX swaps.
  document.addEventListener("click", function (event) {
    if (!modalIsOpen()) {
      return;
    }
    if (event.target.closest(".modal-close")) {
      closeModal();
      return;
    }
    if (event.target === backdrop) {
      closeModal();
    }
  });

  // Escape closes; "/" focuses the search box from anywhere outside a text
  // field; Tab keeps focus inside the dialog while it is open.
  document.addEventListener("keydown", function (event) {
    if (event.key === "/" && !modalIsOpen()) {
      var target = event.target;
      var typing =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target instanceof HTMLSelectElement ||
        (target.isContentEditable && target.isContentEditable === true);
      if (!typing) {
        event.preventDefault();
        if (searchBox !== null) {
          searchBox.focus();
        }
      }
      return;
    }
    if (!modalIsOpen()) {
      return;
    }
    if (event.key === "Escape") {
      closeModal();
      return;
    }
    if (event.key === "Tab") {
      trapFocus(event);
    }
  });

  function trapFocus(event) {
    var dialog = backdrop.querySelector(".modal-dialog");
    var focusable = dialog.querySelectorAll(
      "a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex='-1'])"
    );
    if (focusable.length === 0) {
      event.preventDefault();
      return;
    }
    var first = focusable[0];
    var last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  // HTMX opens the modal whenever a fragment lands in #audit-modal-content;
  // inventory swaps re-apply the active filter to the fresh rows.
  document.body.addEventListener("htmx:afterSwap", function (event) {
    if (event.target && event.target.id === "audit-modal-content") {
      openModal();
      return;
    }
    if (event.target && event.target.id === "identity-list") {
      filterRows();
    }
  });

  // Select-on-focus for the read-only credential disclosures, replacing the
  // former inline onfocus handler so the CSP can keep banning inline script.
  document.addEventListener("focusin", function (event) {
    var textarea = event.target;
    if (textarea instanceof HTMLTextAreaElement && textarea.readOnly) {
      textarea.select();
    }
  });
})();
