(() => {
  const CONTENT_ID = "table-of-contents-content";
  const ROOT_SELECTOR = ':scope > li:has(> a[href^="#"])';
  const TOGGLE_CLASS = "msb-toc-toggle";

  const directLink = (item) =>
    Array.from(item.children).find(
      (child) => child.tagName === "A" && child.getAttribute("href")?.startsWith("#"),
    );

  const directList = (item) =>
    Array.from(item.children).find((child) => child.tagName === "UL");

  const setExpanded = (item, toggle, expanded) => {
    item.dataset.msbExpanded = String(expanded);
    toggle.setAttribute("aria-expanded", String(expanded));
    toggle.setAttribute(
      "aria-label",
      `${expanded ? "Collapse" : "Expand"} ${directLink(item)?.textContent?.trim() ?? "section"}`,
    );
  };

  const enhance = () => {
    const content = document.getElementById(CONTENT_ID);
    if (!content) return;

    for (const item of content.querySelectorAll(ROOT_SELECTOR)) {
      const childList = directList(item);
      const link = directLink(item);
      const existingToggle = item.querySelector(`:scope > .${TOGGLE_CLASS}`);
      if (!childList || !link) continue;
      if (existingToggle) {
        if (item.hasAttribute("data-active") && item.dataset.msbExpanded !== "true") {
          setExpanded(item, existingToggle, true);
        }
        continue;
      }

      const toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = TOGGLE_CLASS;
      toggle.innerHTML = '<span aria-hidden="true"></span>';
      toggle.addEventListener("click", () => {
        setExpanded(item, toggle, item.dataset.msbExpanded !== "true");
      });

      item.insertBefore(toggle, link);
      setExpanded(item, toggle, item.hasAttribute("data-active"));
    }
  };

  const observer = new MutationObserver(enhance);

  const start = () => {
    enhance();
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["data-active"],
    });
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
})();
