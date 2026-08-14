(() => {
  const CONTENT_ID = "table-of-contents-content";
  const ROOT_SELECTOR = ':scope > li:has(> a[href^="#"])';
  const TOGGLE_CLASS = "msb-toc-toggle";
  const MANUAL_COLLAPSE_ATTRIBUTE = "data-msb-manually-collapsed";

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

  const collapsePeers = (item) => {
    for (const peer of item.parentElement?.querySelectorAll(ROOT_SELECTOR) ?? []) {
      if (peer === item) continue;
      const peerToggle = peer.querySelector(`:scope > .${TOGGLE_CLASS}`);
      if (peerToggle) setExpanded(peer, peerToggle, false);
    }
  };

  const enhance = () => {
    const content = document.getElementById(CONTENT_ID);
    if (!content) return;

    for (const item of content.querySelectorAll(ROOT_SELECTOR)) {
      const childList = directList(item);
      const link = directLink(item);
      const existingToggle = item.querySelector(`:scope > .${TOGGLE_CLASS}`);
      if (!childList || !link) continue;
      if (existingToggle) continue;

      const toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = TOGGLE_CLASS;
      toggle.innerHTML = '<span aria-hidden="true"></span>';
      toggle.addEventListener("click", () => {
        const expanded = item.dataset.msbExpanded !== "true";
        if (expanded) {
          item.removeAttribute(MANUAL_COLLAPSE_ATTRIBUTE);
          collapsePeers(item);
        } else {
          item.setAttribute(MANUAL_COLLAPSE_ATTRIBUTE, "true");
        }
        setExpanded(item, toggle, expanded);
      });
      link.addEventListener("click", () => {
        if (item.dataset.msbExpanded === "true") return;
        item.removeAttribute(MANUAL_COLLAPSE_ATTRIBUTE);
        collapsePeers(item);
        setExpanded(item, toggle, true);
      });

      item.insertBefore(toggle, link);
      setExpanded(item, toggle, item.hasAttribute("data-active"));
    }
  };

  const observer = new MutationObserver((records) => {
    enhance();

    for (const record of records) {
      if (record.type !== "attributes" || record.attributeName !== "data-active") continue;
      const item = record.target;
      if (!(item instanceof HTMLElement) || !item.hasAttribute("data-active")) continue;
      if (item.getAttribute(MANUAL_COLLAPSE_ATTRIBUTE) === "true") continue;

      const toggle = item.querySelector(`:scope > .${TOGGLE_CLASS}`);
      if (!toggle) continue;
      collapsePeers(item);
      setExpanded(item, toggle, true);
    }
  });

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
