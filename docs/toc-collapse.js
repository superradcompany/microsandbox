// Mintlify automatically loads every .js file in the documentation content directory.
(() => {
  const CONTENT_ID = "table-of-contents-content";
  const ROOT_SELECTOR = ':scope > li:has(> a[href^="#"])';
  const TOGGLE_CLASS = "msb-toc-toggle";
  const MANUAL_COLLAPSE_ATTRIBUTE = "data-msb-manually-collapsed";
  const ACTIVE_HEADING_OFFSET = 120;

  const directLink = (item) =>
    Array.from(item.children).find(
      (child) => child.tagName === "A" && child.getAttribute("href")?.startsWith("#"),
    );

  const directList = (item) =>
    Array.from(item.children).find((child) => child.tagName === "UL");

  const headingFor = (item) => {
    const href = directLink(item)?.getAttribute("href");
    if (!href?.startsWith("#")) return null;

    try {
      return document.getElementById(decodeURIComponent(href.slice(1)));
    } catch {
      return null;
    }
  };

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

  const syncActiveRoot = () => {
    const content = document.getElementById(CONTENT_ID);
    if (!content) return;

    const roots = Array.from(content.querySelectorAll(ROOT_SELECTOR));
    const sections = roots
      .map((item) => ({ item, heading: headingFor(item) }))
      .filter(({ heading }) => heading);
    if (sections.length === 0) return;

    let active = sections[0].item;
    for (const section of sections) {
      if (section.heading.getBoundingClientRect().top <= ACTIVE_HEADING_OFFSET) {
        active = section.item;
      } else {
        break;
      }
    }

    const last = sections.at(-1);
    const atPageBottom =
      window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 2;
    if (atPageBottom && last.heading.getBoundingClientRect().top < window.innerHeight) {
      active = last.item;
    }

    for (const { item } of sections) {
      item.toggleAttribute("data-active", item === active);
    }

    if (active.getAttribute(MANUAL_COLLAPSE_ATTRIBUTE) === "true") return;
    const toggle = active.querySelector(`:scope > .${TOGGLE_CLASS}`);
    if (!toggle) return;
    collapsePeers(active);
    setExpanded(active, toggle, true);
  };

  let activeSyncFrame = null;
  const scheduleActiveSync = () => {
    if (activeSyncFrame !== null) return;
    activeSyncFrame = window.requestAnimationFrame(() => {
      activeSyncFrame = null;
      syncActiveRoot();
    });
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
        scheduleActiveSync();
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
    scheduleActiveSync();

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
    scheduleActiveSync();
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["data-active"],
    });
    window.addEventListener("scroll", scheduleActiveSync, { passive: true });
    window.addEventListener("resize", scheduleActiveSync);
    window.addEventListener("hashchange", scheduleActiveSync);
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
})();
