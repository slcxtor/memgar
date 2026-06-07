/* Make the "Memgar" site title in the header a link to the home page.
 *
 * mkdocs-material's default markup wraps the site name in a <span>, not an
 * <a>. The leftmost logo button is already clickable, but users reasonably
 * expect the title text itself to be a link too. This script finds the first
 * .md-header__topic (the static site-name row, not the per-page topic that
 * appears on scroll) and turns its inner text into an anchor pointing to the
 * canonicalised base URL.
 */
(function () {
  "use strict";

  function base() {
    // mkdocs writes the canonical base URL on <body data-md-component="container">.
    // Falls back to "/" if not present (e.g. local file://).
    var meta = document.querySelector('link[rel="canonical"]');
    if (meta && meta.href) {
      try {
        var url = new URL(meta.href);
        // Site root: keep origin + the part above the current page path.
        // Easiest reliable choice is the configured site_url root, which on
        // any built page is one "../" hop per nav level. Compute it from the
        // logo button instead — it already points at the root.
      } catch (e) { /* fall through */ }
    }
    var logo = document.querySelector("a.md-header__button.md-logo");
    return (logo && logo.getAttribute("href")) || "/";
  }

  function wireUp() {
    var topic = document.querySelector(
      ".md-header__title .md-header__topic:first-child .md-ellipsis"
    );
    if (!topic || topic.dataset.memgarHomeLink === "1") return;

    var href = base();
    var label = topic.textContent;

    var a = document.createElement("a");
    a.href = href;
    a.textContent = label;
    a.setAttribute("aria-label", label + " — home");
    a.style.color = "inherit";
    a.style.textDecoration = "none";

    topic.textContent = "";
    topic.appendChild(a);
    topic.dataset.memgarHomeLink = "1";
  }

  // Run on initial load and again after Material's instant-navigation swaps
  // the DOM (the title element is re-rendered between pages).
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wireUp);
  } else {
    wireUp();
  }
  document.addEventListener("DOMContentSwitch", wireUp);
  if (window.document$ && typeof window.document$.subscribe === "function") {
    window.document$.subscribe(wireUp);
  }
})();
