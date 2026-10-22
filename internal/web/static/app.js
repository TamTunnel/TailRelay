// Tailrelay UI helpers. Kept in an external file so the Content-Security-Policy
// can forbid all inline scripts.
document.addEventListener("DOMContentLoaded", function () {
  // Forms with data-confirm ask before submitting (e.g. client removal).
  document.querySelectorAll("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      if (!window.confirm(f.getAttribute("data-confirm"))) {
        e.preventDefault();
      }
    });
  });
});
