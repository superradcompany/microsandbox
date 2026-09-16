// The main scrollbar is a fixed overlay, so showing it never changes layout.
(() => {
  // Keep the native scrollbar in viewers that cannot maintain the overlay.
  if (typeof ResizeObserver !== "function") return;
  const root = document.documentElement;
  if (document.getElementById("msb-page-scrollbar")) return;
  const track = document.createElement("div");
  const thumb = document.createElement("div");
  track.id = "msb-page-scrollbar";
  track.setAttribute("role", "scrollbar");
  track.setAttribute("aria-label", "Scroll page");
  track.setAttribute("aria-orientation", "vertical");
  track.setAttribute("aria-valuemin", "0");
  track.tabIndex = 0;
  thumb.className = "msb-page-scrollbar-thumb";
  track.append(thumb);
  document.body.append(track);
  let timer, frame, dragOffset = null;
  let nearEdge = false;

  const metrics = () => {
    const height = Math.max(0, window.innerHeight - 8);
    const max = Math.max(0, root.scrollHeight - window.innerHeight);
    const size = Math.min(height, Math.max(28, height * window.innerHeight / root.scrollHeight));
    return { height, max, size, travel: height - size };
  };
  const update = () => {
    const { max, size, travel } = metrics();
    track.hidden = max === 0;
    thumb.style.height = `${size}px`;
    thumb.style.transform = `translateY(${max ? window.scrollY / max * travel : 0}px)`;
    track.setAttribute("aria-valuemax", String(max));
    track.setAttribute("aria-valuenow", String(Math.round(window.scrollY)));
  };
  const reveal = () => {
    track.dataset.active = "true";
    clearTimeout(timer);
    if (!nearEdge && dragOffset === null && document.activeElement !== track) {
      timer = setTimeout(() => delete track.dataset.active, 900);
    }
  };
  const schedule = () => {
    if (frame) return;
    frame = requestAnimationFrame(() => { frame = null; update(); });
  };
  window.addEventListener("scroll", () => { schedule(); reveal(); }, { passive: true });
  window.addEventListener("resize", schedule);
  const observer = new ResizeObserver(schedule);
  observer.observe(document.body);
  observer.observe(root);
  window.addEventListener("pointermove", (event) => {
    const next = event.clientX >= window.innerWidth - 16;
    if (nearEdge !== next) { nearEdge = next; reveal(); }
  }, { passive: true });
  const drag = (event) => {
    const { max, travel } = metrics();
    const y = event.clientY - track.getBoundingClientRect().top - dragOffset;
    window.scrollTo({ top: travel ? Math.max(0, Math.min(1, y / travel)) * max : 0, behavior: "instant" });
  };
  track.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    event.preventDefault();
    dragOffset = event.target === thumb ? event.clientY - thumb.getBoundingClientRect().top : metrics().size / 2;
    track.setPointerCapture(event.pointerId);
    reveal();
    drag(event);
  });
  track.addEventListener("pointermove", (event) => { if (dragOffset !== null) drag(event); });
  const endDrag = () => { dragOffset = null; reveal(); };
  track.addEventListener("lostpointercapture", endDrag);
  track.addEventListener("pointerup", endDrag);
  track.addEventListener("pointercancel", endDrag);
  track.addEventListener("focus", reveal);
  track.addEventListener("blur", reveal);
  track.addEventListener("keydown", (event) => {
    const positions = { ArrowDown: window.scrollY + 40, ArrowUp: window.scrollY - 40,
      PageDown: window.scrollY + window.innerHeight * .9, PageUp: window.scrollY - window.innerHeight * .9,
      Home: 0, End: metrics().max };
    if (!(event.key in positions)) return;
    event.preventDefault();
    window.scrollTo({ top: positions[event.key], behavior: "instant" });
    reveal();
  });
  window.addEventListener("blur", () => { dragOffset = null; nearEdge = false; reveal(); });
  update();
  // Hide the native scrollbar only after the overlay is ready.
  root.setAttribute("data-msb-overlay-scrollbar", "");
})();
