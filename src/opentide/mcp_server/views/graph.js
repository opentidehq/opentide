  // ------------------------------------------------------------ detection graph
  // Injected into view.html's script for ui://opentide/graph.html: it uses the shell's
  // bridge (callTool, sendToChat, request), helpers (el, render, header, plural) and the
  // embedded ATT&CK matrix (attack). Data: the graph tool, detail "full".

  const SVG_NS = "http://www.w3.org/2000/svg";
  function svg(tag, attributes, ...children) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [key, value] of Object.entries(attributes || {})) {
      if (value === undefined || value === null || value === false) continue;
      if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, String(value));
    }
    for (const child of children.flat(Infinity)) {
      if (child === undefined || child === null || child === false) continue;
      node.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  // The workspace's [[statuses]] (graph full): a RELEASE status is "in production", a PREVIEW one
  // is on its way, anything else (INERT, DISABLEMENT, DELETION) is neither. Without the list,
  // the default lifecycle's names.
  let STATUSES = [
    { name: "DESIGN", strategy: "INERT" }, { name: "DEVELOPMENT", strategy: "PREVIEW" }, { name: "IMPROVING", strategy: "PREVIEW" },
    { name: "STAGING", strategy: "PREVIEW" }, { name: "ACCEPTANCE", strategy: "PREVIEW" }, { name: "PRODUCTION", strategy: "RELEASE" },
    { name: "DISABLED", strategy: "DISABLEMENT" }, { name: "REMOVED", strategy: "DELETION" },
  ];
  const strategyOf = (status) => (STATUSES.find((entry) => entry.name === status) || {}).strategy;
  const isRelease = (status) => strategyOf(status) === "RELEASE";
  const isPreview = (status) => strategyOf(status) === "PREVIEW";
  const statusClass = (status) => (isRelease(status) ? "prod" : isPreview(status) ? "stage" : "other");
  // Released first, then the lifecycle backwards (closest to release first), then the rest.
  const statusRank = (status) => {
    const index = STATUSES.findIndex((entry) => entry.name === status);
    if (index < 0) return STATUSES.length + 1;
    return isRelease(status) ? -1 : isPreview(status) ? STATUSES.length - index : STATUSES.length + index;
  };
  const CRITICALITY = { Critical: 0, Severe: 0, High: 1, Medium: 2, Moderate: 2, Low: 3 };
  const SEQUENCE = { preceeds: "forward", succeeds: "backward" };
  // Chaining relations in words, read from the threat that declares them and from the other
  // end (chaining_relations vocabulary: "T preceeds V" means V happens after T).
  const RELATION_WORDS = {
    preceeds: ["comes before", "comes after"], succeeds: ["comes after", "comes before"],
    implemented: ["is implemented by", "implements"], implements: ["implements", "is implemented by"],
    enabled: ["enables", "is enabled by"], enabling: ["is enabled by", "enables"], synergize: ["works with", "works with"],
  };
  const relationWords = (link) => (RELATION_WORDS[link.relation] || [link.relation, link.relation])[link.inverse ? 1 : 0];
  const RELATION_FAMILY = { preceeds: "sequence", succeeds: "sequence", implemented: "atomicity", implements: "atomicity", enabled: "support", enabling: "support", synergize: "support" };

  /** ATT&CK lookups from the embedded matrix: technique -> {name, tactics, link}. */
  const techniqueInfo = new Map();
  if (attack && Array.isArray(attack.tactics)) {
    for (const tactic of attack.tactics) {
      for (const technique of tactic.techniques) {
        const known = techniqueInfo.get(technique.id) || { name: technique.name, tactics: [], link: technique.link };
        known.tactics.push(tactic.name);
        techniqueInfo.set(technique.id, known);
        for (const sub of technique.subs || []) {
          if (!techniqueInfo.has(sub.id)) techniqueInfo.set(sub.id, { name: technique.name + ": " + sub.name, tactics: known.tactics, link: "" });
        }
      }
    }
  }
  const tacticsOf = (technique) => (techniqueInfo.get(technique) || techniqueInfo.get(String(technique).split(".")[0]) || { tactics: [] }).tactics;
  const tacticNames = attack && Array.isArray(attack.tactics) ? attack.tactics.map((tactic) => tactic.name) : [];

  /** The catalogue as indexed nodes with up (towards actors) and down (towards platforms) links. */
  function buildModel(data) {
    if (Array.isArray(data.statuses) && data.statuses.length) STATUSES = data.statuses;
    const nodes = new Map();
    const add = (id, kind, title, extra) => {
      if (!nodes.has(id)) nodes.set(id, Object.assign({ id, kind, title, up: new Set(), down: new Set(), chain: [] }, extra));
      return nodes.get(id);
    };
    const link = (from, to) => { from.down.add(to.id); to.up.add(from.id); };
    const actorNames = data.actor_names || {};
    for (const threat of data.threats || []) add(threat.uuid, "threat", threat.title, { data: threat });
    for (const objective of data.objectives || []) add(objective.uuid, "objective", objective.title, { data: objective });
    for (const rule of data.rules || []) add(rule.uuid, "rule", rule.title, { data: rule });
    for (const threat of data.threats || []) {
      // "[Enterprise] APT29": the matrix prefix says nothing the graph needs.
      const label = (actor) => String(actorNames[actor] || actor).replace(/^\[[^\]]+\]\s*/, "");
      for (const actor of threat.actors || []) link(add("actor:" + actor, "actor", label(actor), { data: { id: actor } }), nodes.get(threat.uuid));
      for (const chained of threat.chaining || []) {
        if (!nodes.has(chained.to)) continue;
        // Validated catalogues scope a relation by its family: "sequence::preceeds".
        const relation = String(chained.relation).split("::").pop();
        nodes.get(threat.uuid).chain.push({ to: chained.to, relation });
        nodes.get(chained.to).chain.push({ to: threat.uuid, relation, inverse: true });
      }
    }
    const missing = [];
    for (const objective of data.objectives || []) {
      for (const threat of objective.threats || []) {
        if (nodes.has(threat) && nodes.get(threat).kind === "threat") link(nodes.get(threat), nodes.get(objective.uuid));
        else missing.push({ from: objective.uuid, to: threat });
      }
    }
    for (const rule of data.rules || []) {
      const objective = rule.objective && nodes.get(rule.objective);
      if (objective && objective.kind === "objective") link(objective, nodes.get(rule.uuid));
      else if (rule.objective) missing.push({ from: rule.uuid, to: rule.objective });
      for (const [platform, status] of Object.entries(rule.platforms || {})) {
        link(nodes.get(rule.uuid), add("platform:" + platform, "platform", platform.replace(/_/g, " "), { data: { name: platform } }));
        nodes.get(rule.uuid).statuses = Object.assign(nodes.get(rule.uuid).statuses || {}, { [platform]: status });
      }
    }
    // Rules reachable from each threat and objective, with their best status: what "covered" means.
    const rulesUnder = (node) => {
      if (node.kind === "rule") return [node];
      if (node.kind === "objective") return Array.from(node.down, (id) => nodes.get(id)).filter((child) => child.kind === "rule");
      if (node.kind === "threat") return Array.from(node.down, (id) => nodes.get(id)).flatMap(rulesUnder);
      return [];
    };
    for (const node of nodes.values()) {
      if (node.kind !== "threat" && node.kind !== "objective") continue;
      node.rules = Array.from(new Set(rulesUnder(node)));
      const statuses = node.rules.flatMap((rule) => Object.values(rule.statuses || {}));
      node.coverage = !node.rules.length ? "blind" : statuses.some(isRelease) ? "covered" : "partial";
    }
    return { nodes, missing };
  }

  /** Everything upstream and downstream of *ids* (lineage, not siblings), plus chained threats. */
  function closure(model, ids, withChains) {
    const seen = new Set();
    const walk = (start, direction) => {
      const stack = [start];
      while (stack.length) {
        const id = stack.pop();
        const node = model.nodes.get(id);
        if (!node) continue;
        for (const next of node[direction]) if (!seen.has(direction + "|" + next)) { seen.add(direction + "|" + next); stack.push(next); }
      }
    };
    // Keys are "direction|id": an id is never parsed, whatever it ends with.
    for (const id of ids) { seen.add("up|" + id); seen.add("down|" + id); walk(id, "up"); walk(id, "down"); }
    const result = new Set(Array.from(seen, (key) => key.slice(key.indexOf("|") + 1)));
    if (withChains) for (const id of ids) for (const link of (model.nodes.get(id) || { chain: [] }).chain) result.add(link.to);
    return result;
  }

  // ----------------------------------------------------------------- state
  const graph = {
    summary: null, model: null, tab: "graph", selected: null, hover: null,
    filters: { text: "", actor: "", tactic: "", platform: "", status: "", gaps: false },
    expanded: new Set(), loading: false, error: null, panelResult: null,
  };

  function renderGraphView(data) {
    if (data && data.error) return render(header("Detection graph"), el("div", { class: "error-box" }, data.error));
    if (data && Array.isArray(data.threats)) {
      graph.model = buildModel(data);
      graph.full = data;
      return paint();
    }
    graph.summary = data;
    if (!graph.model && canCallTools() && !graph.loading) {
      graph.loading = true;
      callTool("graph", { detail: "full" })
        .then((full) => { graph.loading = false; if (full && full.error) graph.error = full.error; else { graph.full = full; graph.model = buildModel(full); } paint(); })
        .catch((error) => { graph.loading = false; graph.error = error.message; paint(); });
    }
    paint();
  }
  extraRenderers.graph = renderGraphView;

  function paint() {
    const tabs = el("div", { class: "g-tabs", role: "tablist", "aria-label": "Graph views" },
      [["graph", "Graph"], ["paths", "Attack paths"], ["portfolio", "Portfolio"]].map(([key, label]) =>
        el("button", { role: "tab", "aria-selected": String(graph.tab === key), onclick: () => { graph.tab = key; paint(); } }, label)));
    const modes = hostContext.availableDisplayModes || [];
    const fullscreen = modes.includes("fullscreen")
      ? el("button", { onclick: () => toggleFullscreen() }, hostContext.displayMode === "fullscreen" ? "Exit full screen" : "Full screen")
      : null;
    const top = header("Detection graph", tabs, fullscreen);
    if (!graph.model) {
      const body = graph.error ? el("div", { class: "error-box" }, graph.error)
        : graph.loading ? state("Loading the catalogue…")
        : state("This host cannot call opentide's tools from the view, so only the summary shows.");
      return render(top, graph.summary ? summaryStats(graph.summary) : null, body, graph.summary ? summaryGaps(graph.summary) : null);
    }
    const body = graph.tab === "paths" ? renderPaths() : graph.tab === "portfolio" ? renderPortfolio() : renderGraphTab();
    render(top, modelStats(), body);
  }

  async function toggleFullscreen() {
    const mode = hostContext.displayMode === "fullscreen" ? "inline" : "fullscreen";
    try {
      const result = await request("ui/request-display-mode", { mode });
      hostContext.displayMode = (result && result.mode) || mode;
      document.documentElement.dataset.display = hostContext.displayMode;
    } catch (_) { /* the host kept its mode */ }
    paint();
  }

  function modelStats() {
    const nodes = Array.from(graph.model.nodes.values());
    const count = (kind) => nodes.filter((node) => node.kind === kind).length;
    const threats = nodes.filter((node) => node.kind === "threat");
    const covered = threats.filter((node) => node.coverage === "covered").length;
    const blind = threats.filter((node) => node.coverage === "blind").length;
    return el("div", { class: "g-stats" },
      el("span", null, el("b", null, String(count("threat"))), " threats"),
      el("span", null, el("b", null, String(count("objective"))), " objectives"),
      el("span", null, el("b", null, String(count("rule"))), " rules"),
      el("span", null, el("b", null, String(count("platform"))), " platforms"),
      el("span", null, el("b", null, threats.length ? Math.round(100 * covered / threats.length) + "%" : "–"), " of threats detected in production"),
      blind ? el("span", null, el("b", { style: "color: var(--g-blind)" }, String(blind)), " blind threats") : null);
  }

  function summaryStats(summary) {
    const counts = summary.counts || {};
    return el("div", { class: "g-stats" }, Object.entries(counts).map(([key, value]) => el("span", null, el("b", null, String(value)), " " + key.replace(/_/g, " "))));
  }
  function summaryGaps(summary) {
    const lists = [["threats_without_rules", "Threats without rules"], ["threats_without_objectives", "Threats without objectives"], ["objectives_without_rules", "Objectives without rules"]];
    return el("div", { class: "g-gaps" }, lists.filter(([key]) => summary[key] && summary[key].count).map(([key, label]) =>
      el("section", { class: "card" }, el("div", { class: "card-head" }, el("strong", null, label), el("span", { class: "faint" }, String(summary[key].count))),
        el("div", { class: "card-body" }, el("ul", null, summary[key].items.map((item) => el("li", null, item.title)))))));
  }

  // ------------------------------------------------------------ graph tab
  const COLUMNS = [["actor", "Actors"], ["threat", "Threats"], ["objective", "Objectives"], ["rule", "Rules"], ["platform", "Platforms"]];
  const NODE_H = 30, NODE_GAP = 8, TOP = 34, GROUP_AT = 4;

  /** The node ids the filters keep: each active filter's matches with their lineage, intersected. */
  function visibleIds() {
    const model = graph.model, f = graph.filters, all = Array.from(model.nodes.values());
    const sets = [];
    const keep = (predicate) => sets.push(closure(model, all.filter(predicate).map((node) => node.id), false));
    if (f.text) {
      const needle = f.text.toLowerCase();
      keep((node) => node.title.toLowerCase().includes(needle) || node.id.toLowerCase().includes(needle));
    }
    if (f.actor) keep((node) => node.id === "actor:" + f.actor);
    if (f.platform) keep((node) => node.id === "platform:" + f.platform);
    if (f.status) keep((node) => node.kind === "rule" && Object.values(node.statuses || {}).includes(f.status));
    if (f.tactic) keep((node) => (node.kind === "threat" || node.kind === "rule") && (node.data.techniques || []).some((t) => tacticsOf(t).includes(f.tactic)));
    if (f.gaps) keep((node) => (node.kind === "threat" || node.kind === "objective") && node.coverage === "blind");
    if (!sets.length) return new Set(model.nodes.keys());
    return sets.reduce((acc, set) => new Set(Array.from(acc).filter((id) => set.has(id))));
  }

  /** Columns of laid-out items; an objective's rules fold into one group node past GROUP_AT. */
  function layout(visible, width) {
    const model = graph.model;
    const narrow = width < 640;
    const columns = COLUMNS.filter(([kind]) => !narrow || (kind !== "actor" && kind !== "platform"));
    const items = new Map(columns.map(([kind]) => [kind, []]));
    for (const node of model.nodes.values()) {
      if (!visible.has(node.id) || !items.has(node.kind) || node.kind === "rule") continue;
      items.get(node.kind).push({ id: node.id, node, members: [node] });
    }
    // Rules: per objective, folded when many and not expanded.
    const ruleItems = items.get("rule");
    const byParent = new Map();
    for (const node of model.nodes.values()) {
      if (node.kind !== "rule" || !visible.has(node.id)) continue;
      const parent = Array.from(node.up)[0] || "(none)";
      if (!byParent.has(parent)) byParent.set(parent, []);
      byParent.get(parent).push(node);
    }
    for (const [parent, rules] of byParent) {
      if (rules.length >= GROUP_AT && !graph.expanded.has(parent) && !rules.some((rule) => rule.id === graph.selected)) {
        ruleItems.push({ id: "group:" + parent, group: parent, members: rules, node: { kind: "rule", title: plural(rules.length, "rule") } });
      } else {
        for (const rule of rules) ruleItems.push({ id: rule.id, node: rule, members: [rule] });
      }
    }
    // Order: threats by criticality, then each column by the mean position of its links (two sweeps).
    const position = new Map();
    const place = (kind) => items.get(kind) && items.get(kind).forEach((item, index) => item.members.forEach((member) => position.set(member.id, index)));
    const neighbours = (item) => item.members.flatMap((member) => Array.from(member.up).concat(Array.from(member.down)));
    const byMean = (kind) => {
      const list = items.get(kind);
      if (!list) return;
      const mean = (item) => { const known = neighbours(item).filter((id) => position.has(id)).map((id) => position.get(id)); return known.length ? known.reduce((a, b) => a + b, 0) / known.length : Infinity; };
      list.sort((a, b) => mean(a) - mean(b) || a.node.title.localeCompare(b.node.title));
      place(kind);
    };
    // Threats in attack-path order (each path's steps in sequence, so chaining arcs are short
    // hops), then the threats on no path by criticality. Everything else follows them.
    const threats = items.get("threat");
    const pathOrder = new Map();
    const { paths } = attackPaths();
    paths.forEach((path) => path.layers.flat().forEach((threat) => { if (!pathOrder.has(threat.id)) pathOrder.set(threat.id, pathOrder.size); }));
    const rank = (item) => (pathOrder.has(item.id) ? pathOrder.get(item.id) : pathOrder.size + (CRITICALITY[item.node.data.criticality] ?? 9));
    threats.sort((a, b) => rank(a) - rank(b) || a.node.title.localeCompare(b.node.title));
    place("threat");
    for (const kind of ["objective", "rule", "platform", "actor", "objective", "rule"]) byMean(kind);

    const gap = 26;
    const colWidth = Math.max(120, Math.floor((width - gap * (columns.length + 1)) / columns.length));
    const placed = new Map();
    let height = TOP;
    columns.forEach(([kind], column) => {
      const x = gap + column * (colWidth + gap);
      items.get(kind).forEach((item, index) => {
        const y = TOP + index * (NODE_H + NODE_GAP);
        item.x = x; item.y = y; item.w = colWidth; item.kind = kind;
        for (const member of item.members) placed.set(member.id, item);
        height = Math.max(height, y + NODE_H + 12);
      });
    });
    return { columns, items, placed, colWidth, gap, height };
  }

  const measure = (() => { const context = document.createElement("canvas").getContext("2d"); return (text, font) => { context.font = font; return context.measureText(text).width; }; })();
  function fit(text, width, font) {
    if (measure(text, font) <= width) return text;
    let low = 0, high = text.length;
    while (low < high) { const mid = (low + high + 1) >> 1; if (measure(text.slice(0, mid) + "…", font) <= width) low = mid; else high = mid - 1; }
    return text.slice(0, low) + "…";
  }

  let graphRefs = null;
  function renderGraphTab() {
    const model = graph.model;
    const visible = visibleIds();
    const canvas = el("div", { class: "g-canvas" });
    const viewport = document.documentElement.clientWidth;
    const panelShown = Boolean(graph.selected && model.nodes.get(graph.selected)) && viewport > 760;
    const width = Math.max(420, Math.min(viewport - 36 - (panelShown ? 300 : 0), 1600));
    const L = layout(visible, width);
    const edges = [], nodeEls = new Map(), edgeEls = [];
    const font = "12px " + getComputedStyle(document.body).fontFamily;

    const edgeLayer = svg("g");
    const seenEdge = new Set();
    for (const item of [].concat(...L.items.values())) {
      for (const member of item.members) {
        for (const downId of member.down) {
          const target = L.placed.get(downId);
          if (!target || target === item) continue;
          const key = item.id + ">" + target.id;
          if (seenEdge.has(key)) continue;
          seenEdge.add(key);
          let cls = "g-edge";
          if (item.kind === "rule" && target.kind === "platform") {
            const statuses = item.members.map((rule) => (rule.statuses || {})[target.node.data.name]);
            cls += " " + (statuses.some(isRelease) ? "prod" : statuses.some(isPreview) ? "stage" : "");
          }
          const x1 = item.x + item.w, y1 = item.y + NODE_H / 2, x2 = target.x, y2 = target.y + NODE_H / 2, mid = (x1 + x2) / 2;
          const path = svg("path", { class: cls, d: `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}` });
          path.dataset.ends = item.id + " " + target.id;
          edgeEls.push(path); edgeLayer.append(path);
        }
      }
    }
    // Threat chaining: arcs on the left of the threat column.
    for (const item of L.items.get("threat") || []) {
      for (const link of item.node.chain) {
        if (link.inverse) continue;
        const target = L.placed.get(link.to);
        if (!target) continue;
        const y1 = item.y + NODE_H / 2, y2 = target.y + NODE_H / 2, x = item.x;
        // Stay in the gutter left of the threat column.
        const bulge = Math.min(L.gap - 3, 8 + Math.abs(y2 - y1) / 12);
        const forward = SEQUENCE[link.relation] !== "backward";
        const [from, to] = forward ? [[x, y1], [x, y2]] : [[x, y2], [x, y1]];
        const path = svg("path", { class: "g-edge chain " + (RELATION_FAMILY[link.relation] || ""), d: `M${from[0]},${from[1]} C${x - bulge},${from[1]} ${x - bulge},${to[1]} ${to[0]},${to[1]}`, "marker-end": "url(#g-arrow)" },
          svg("title", null, item.node.title + " " + relationWords(link) + " " + target.node.title));
        path.dataset.ends = item.id + " " + target.id;
        edgeEls.push(path); edgeLayer.append(path);
      }
    }

    const nodeLayer = svg("g");
    const kindColor = { actor: "var(--g-actor)", threat: "var(--g-threat)", objective: "var(--g-objective)", rule: "var(--g-rule)", platform: "var(--g-platform)" };
    for (const item of [].concat(...L.items.values())) {
      const node = item.node;
      let subtitle = "";
      if (item.group) subtitle = "click to expand";
      else if (node.kind === "threat") subtitle = [node.data.criticality, node.coverage === "blind" ? "no rule" : plural(node.rules.length, "rule")].filter(Boolean).join(" · ");
      else if (node.kind === "objective") subtitle = node.coverage === "blind" ? "no rule" : plural(node.rules.length, "rule");
      else if (node.kind === "rule") subtitle = Object.entries(node.statuses || {}).map(([p, s]) => p.replace(/_/g, " ") + (s ? " " + s.toLowerCase() : "")).join(", ");
      else if (node.kind === "platform") subtitle = plural(node.up.size, "rule");
      else if (node.kind === "actor") subtitle = plural(node.down.size, "threat");
      const textWidth = item.w - 18;
      const stripe = item.group ? groupStatusColor(item.members) : node.kind === "rule" ? statusColor(node.statuses) : kindColor[node.kind];
      const g = svg("g", {
        class: "g-node" + ((node.coverage === "blind") ? " blind" : "") + (graph.selected === item.id ? " selected" : ""),
        transform: `translate(${item.x},${item.y})`, tabindex: 0, role: "button",
        "aria-label": node.kind + ": " + node.title,
        onclick: () => (item.group ? expandGroup(item.group) : select(item.id)),
        onkeydown: (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); item.group ? expandGroup(item.group) : select(item.id); } },
        onmouseenter: () => highlight(item.id), onmouseleave: () => highlight(null), onfocus: () => highlight(item.id), onblur: () => highlight(null),
      },
        svg("rect", { class: "box", width: item.w, height: NODE_H }),
        svg("rect", { class: "stripe", x: 0, y: 0, width: 4, height: NODE_H, fill: stripe }),
        svg("text", { x: 10, y: 10 }, fit(node.title, textWidth, font)),
        svg("text", { class: "sub", x: 10, y: 22 }, fit(subtitle, textWidth, "10px " + getComputedStyle(document.body).fontFamily)),
        svg("title", null, node.title));
      nodeEls.set(item.id, g);
      for (const member of item.members) nodeEls.set(member.id, g);
      nodeLayer.append(g);
    }
    const heads = L.columns.map(([kind, label], column) => svg("text", { class: "g-colhead", x: L.gap + column * (L.colWidth + L.gap), y: 18 }, label + " " + (L.items.get(kind) || []).reduce((n, item) => n + item.members.length, 0)));
    const drawing = svg("svg", { class: "g-svg", width: L.gap + L.columns.length * (L.colWidth + L.gap), height: L.height, role: "img", "aria-label": "Detection graph" },
      svg("defs", null, svg("marker", { id: "g-arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: "auto-start-reverse" }, svg("path", { d: "M0,0 L10,5 L0,10 z", fill: "var(--g-threat)" }))),
      heads, edgeLayer, nodeLayer);
    canvas.append(drawing);
    graphRefs = { svg: drawing, nodeEls, edgeEls };
    if (graph.selected) applyHighlight(graph.selected);

    const shown = Array.from(visible).filter((id) => model.nodes.has(id) && model.nodes.get(id).kind === "rule").length;
    const panel = graph.selected && model.nodes.get(graph.selected) ? detailPanel(model.nodes.get(graph.selected)) : null;
    return el("div", null,
      toolbar(),
      model.nodes.size && !visible.size ? state("Nothing matches these filters.") : null,
      el("div", { class: "g-layout" + (panel ? "" : " no-panel") }, canvas, panel),
      el("div", { class: "g-legend" },
        el("span", null, el("i", { style: "background: var(--g-actor)" }), "actor"), el("span", null, el("i", { style: "background: var(--g-threat)" }), "threat"),
        el("span", null, el("i", { style: "background: var(--g-objective)" }), "objective"), el("span", null, el("i", { style: "background: var(--g-prod)" }), "rule in production"),
        el("span", null, el("i", { style: "background: var(--g-stage)" }), "in preview (staging, acceptance…)"), el("span", null, el("i", { class: "dash" }), "threat chaining"),
        el("span", null, "dashed outline: no rule"), el("span", null, plural(shown, "rule") + " shown")));
  }

  function statusColorOf(values) {
    return values.some(isRelease) ? "var(--g-prod)" : values.some(isPreview) ? "var(--g-stage)" : "var(--g-other)";
  }
  const statusColor = (statuses) => statusColorOf(Object.values(statuses || {}));
  const groupStatusColor = (rules) => statusColorOf(rules.flatMap((rule) => Object.values(rule.statuses || {})));

  function toolbar() {
    const model = graph.model, f = graph.filters;
    const values = (kind) => Array.from(model.nodes.values()).filter((node) => node.kind === kind);
    const option = (value, label, current) => el("option", { value, selected: value === current }, label);
    const select = (key, label, entries) => el("select", { "aria-label": label, onchange: (event) => { f[key] = event.target.value; graph.selected = null; paint(); } },
      option("", label, f[key]), entries.map(([value, text]) => option(value, text, f[key])));
    const statuses = Array.from(new Set(values("rule").flatMap((rule) => Object.values(rule.statuses || {}).filter(Boolean)))).sort((a, b) => statusRank(a) - statusRank(b));
    const search = el("input", { type: "search", placeholder: "Find a threat, objective, rule or actor", value: f.text, "aria-label": "Find" });
    let timer = null;
    search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { f.text = search.value.trim(); graph.selected = null; paint(); const again = root.querySelector('.g-toolbar input[type="search"]'); if (again) { again.focus(); again.setSelectionRange(again.value.length, again.value.length); } }, 250); });
    const active = f.text || f.actor || f.tactic || f.platform || f.status || f.gaps;
    return el("div", { class: "g-toolbar" }, search,
      select("actor", "All actors", values("actor").map((node) => [node.data.id, node.title]).sort((a, b) => a[1].localeCompare(b[1]))),
      tacticNames.length ? select("tactic", "All tactics", tacticNames.map((name) => [name, name])) : null,
      select("platform", "All platforms", values("platform").map((node) => [node.data.name, node.title]).sort((a, b) => a[1].localeCompare(b[1]))),
      statuses.length ? select("status", "All statuses", statuses.map((status) => [status, status.toLowerCase()])) : null,
      el("label", { class: "g-check" }, el("input", { type: "checkbox", checked: f.gaps, onchange: (event) => { f.gaps = event.target.checked; paint(); } }), "Gaps only"),
      active ? el("button", { onclick: () => { graph.filters = { text: "", actor: "", tactic: "", platform: "", status: "", gaps: false }; graph.selected = null; paint(); } }, "Clear") : null);
  }

  function select(id) {
    graph.selected = graph.selected === id ? null : id;
    graph.panelResult = null;
    paint();
  }
  function expandGroup(parent) { graph.expanded.add(parent); paint(); }
  function focusNode(id) { graph.tab = "graph"; graph.selected = id; graph.panelResult = null; paint(); }

  function highlight(id) { if (!graph.selected) applyHighlight(id); }
  function applyHighlight(id) {
    if (!graphRefs) return;
    const { svg: drawing, nodeEls, edgeEls } = graphRefs;
    if (!id || !graph.model.nodes.has(id)) {
      drawing.classList.remove("dimmed");
      return;
    }
    const lit = closure(graph.model, [id], true);
    drawing.classList.add("dimmed");
    const litEls = new Set(Array.from(lit, (litId) => nodeEls.get(litId)).filter(Boolean));
    for (const g of new Set(nodeEls.values())) g.classList.toggle("on", litEls.has(g));
    // Edge ends are drawn items (a node, or a folded group of rules): lit when both are.
    for (const path of edgeEls) {
      const [from, to] = path.dataset.ends.split(" ");
      path.classList.toggle("on", litEls.has(nodeEls.get(from)) && litEls.has(nodeEls.get(to)));
    }
  }

  // ------------------------------------------------------------- side panel
  function detailPanel(node) {
    const facts = [];
    const fact = (label, value) => { if (value !== undefined && value !== null && value !== "" && !(Array.isArray(value) && !value.length)) facts.push(el("dt", null, label), el("dd", null, value)); };
    const linkTo = (id) => { const target = graph.model.nodes.get(id); return target ? el("button", { class: "g-link", onclick: () => focusNode(id) }, target.title) : el("span", { class: "faint" }, shortUuid(id)); };
    const linkList = (ids) => ids.length ? el("div", null, ids.slice(0, 12).map((id) => el("div", null, linkTo(id))), ids.length > 12 ? el("div", { class: "faint" }, "+" + (ids.length - 12) + " more") : null) : null;
    const techniqueChips = (list) => list && list.length ? el("div", { class: "chips" }, list.map((t) => el("span", { class: "chip h1", title: (techniqueInfo.get(t) || {}).name || t }, t))) : null;
    const actions = [];
    const ask = (label, text) => canMessage() && actions.push(el("button", { onclick: (event) => sendToChat(text).then(() => { event.target.textContent = "Sent to Claude"; event.target.disabled = true; }, () => { event.target.textContent = "Could not send"; }) }, label));
    const d = node.data || {};
    if (node.kind === "threat") {
      fact("Criticality", d.criticality); fact("Severity", d.severity); fact("Viability", d.viability);
      fact("Coverage", el("span", { class: "pill " + (node.coverage === "covered" ? "ok" : node.coverage === "partial" ? "warning" : "error") }, node.coverage === "covered" ? "in production" : node.coverage === "partial" ? "not in production" : "blind"));
      fact("Techniques", techniqueChips(d.techniques));
      fact("Actors", linkList(Array.from(node.up)));
      fact("Objectives", linkList(Array.from(node.down)));
      fact("Chained", node.chain.length ? el("div", null, node.chain.map((link) => el("div", null, el("span", { class: "faint" }, relationWords(link) + " "), linkTo(link.to)))) : null);
      ask(node.coverage === "blind" ? "Ask Claude to plan detections" : "Ask Claude to review coverage",
        (node.coverage === "blind" ? "Plan opentide detection content for the threat " : "Review opentide's detection coverage of the threat ") + `"${node.title}" (${node.id}): read it, check its objectives and rules with get_chaining, and propose what to add.`);
      if (node.chain.length) actions.push(el("button", { onclick: () => { graph.tab = "paths"; paint(); } }, "Show attack paths"));
    } else if (node.kind === "objective") {
      fact("Priority", d.priority); fact("Signals", d.signals);
      fact("Threats", linkList(Array.from(node.up)));
      fact("Rules", linkList(Array.from(node.down)));
      ask("Ask Claude to draft a rule", `Draft an opentide detection rule for the objective "${node.title}" (${node.id}): start from opentide://templates/rule, and validate it with validation_report until ok is true.`);
    } else if (node.kind === "rule") {
      fact("Severity", d.severity);
      fact("Platforms", el("div", null, Object.entries(node.statuses || {}).map(([platform, status]) => el("div", null, platform.replace(/_/g, " ") + " ", el("span", { class: "pill " + (isRelease(status) ? "ok" : isPreview(status) ? "warning" : "neutral") }, (status || "no status").toLowerCase())))));
      fact("Objective", linkList(Array.from(node.up)));
      fact("Techniques", techniqueChips(d.techniques));
      if (canCallTools()) {
        actions.push(el("button", { onclick: () => runPanelTool("validation_report", { uuid: node.id }) }, "Validate"));
        actions.push(el("button", { onclick: () => runPanelTool("deployment_status", { uuid: node.id }) }, "Where is it deployed?"));
      }
      ask("Ask Claude to review this rule", `Review the opentide rule "${node.title}" (${node.id}): its query, its objective and its platforms, and say what it misses.`);
    } else if (node.kind === "platform") {
      const counts = {};
      for (const id of node.up) { const status = ((graph.model.nodes.get(id) || {}).statuses || {})[d.name] || "no status"; counts[status] = (counts[status] || 0) + 1; }
      fact("Rules", el("div", null, Object.entries(counts).sort((a, b) => statusRank(a[0]) - statusRank(b[0])).map(([status, n]) => el("div", null, n + " " + status.toLowerCase()))));
    } else if (node.kind === "actor") {
      fact("Threats", linkList(Array.from(node.down)));
      const threats = Array.from(node.down, (id) => graph.model.nodes.get(id));
      fact("Detected", threats.filter((t) => t.coverage === "covered").length + " of " + threats.length + " threats in production");
      ask("Ask Claude about this actor", `What does our opentide catalogue detect of ${node.title}? Use search with actor ${d.id}, then get_chaining, and list the gaps.`);
    }
    return el("aside", { class: "g-panel", "aria-label": "Details" },
      el("div", { class: "kind" }, node.kind),
      el("h2", null, node.title),
      node.id.includes(":") ? null : el("div", { class: "faint mono" }, node.id),
      facts.length ? el("dl", null, facts) : null,
      actions.length ? el("div", { class: "issue-actions" }, actions) : null,
      graph.panelResult ? el("div", { class: "result" }, graph.panelResult) : null);
  }

  async function runPanelTool(name, args) {
    graph.panelResult = el("span", { class: "faint" }, "Asking opentide…");
    paint();
    try {
      const result = await callTool(name, args);
      graph.panelResult = name === "validation_report" ? validationSummary(result) : deploymentSummary(result);
    } catch (error) {
      graph.panelResult = el("div", { class: "error-box" }, error.message);
    }
    paint();
  }
  function validationSummary(report) {
    if (report.error) return el("div", { class: "error-box" }, report.error);
    const issues = (report.issues || []).concat(report.warnings || []);
    if (report.ok && !issues.length) return el("span", { class: "pill ok" }, "✓ Valid");
    return el("div", null, el("span", { class: "pill " + (report.ok ? "warning" : "error") }, report.ok ? plural(issues.length, "warning") : plural((report.issues || []).length, "error")),
      el("ul", { style: "margin:6px 0 0; padding-left: 16px" }, issues.slice(0, 6).map((issue) => el("li", null, el("code", null, issue.code || "issue"), " ", issue.message || ""))));
  }
  function deploymentSummary(status) {
    if (status.error || status.found === false) return el("div", { class: "error-box" }, status.error || "Not found");
    const rows = Object.entries(status.platforms || {});
    if (!rows.length) return el("span", { class: "faint" }, "No platform block.");
    return el("table", null, el("tr", null, el("th", null, "Platform"), el("th", null, "Deployed"), el("th", null, "Tenants")),
      rows.map(([platform, info]) => el("tr", null, el("td", null, platform.replace(/_/g, " ")), el("td", null, info.deployed ? "yes" : "no"),
        el("td", null, Array.isArray(info.tenants) ? info.tenants.join(", ") : info.tenants && typeof info.tenants === "object" ? Object.keys(info.tenants).join(", ") : ""))),
      status.state_error ? el("tr", null, el("td", { colspan: 3 }, el("span", { class: "faint" }, status.state_error.message || "State unreadable"))) : null);
  }

  // ------------------------------------------------------------ attack paths
  /** Chains of threats joined by sequence relations, ordered earliest first, in layers. */
  function attackPaths() {
    const model = graph.model;
    const threats = Array.from(model.nodes.values()).filter((node) => node.kind === "threat");
    const next = new Map(threats.map((t) => [t.id, new Set()]));
    const related = new Map(threats.map((t) => [t.id, []]));
    for (const threat of threats) {
      for (const link of threat.chain) {
        if (link.inverse) continue;
        const direction = SEQUENCE[link.relation];
        if (direction === "forward") next.get(threat.id).add(link.to);
        else if (direction === "backward") next.get(link.to).add(threat.id);
        else { related.get(threat.id).push(link); }
      }
    }
    // Components over sequence edges.
    const neighbours = new Map(threats.map((t) => [t.id, new Set()]));
    for (const [from, tos] of next) for (const to of tos) { neighbours.get(from).add(to); neighbours.get(to).add(from); }
    const seen = new Set(), paths = [];
    for (const threat of threats) {
      if (seen.has(threat.id) || !neighbours.get(threat.id).size) continue;
      const members = [], stack = [threat.id];
      seen.add(threat.id);
      while (stack.length) { const id = stack.pop(); members.push(id); for (const n of neighbours.get(id)) if (!seen.has(n)) { seen.add(n); stack.push(n); } }
      // Longest-path layers; a cycle's back edges are ignored.
      const inPath = new Set(members);
      const previous = new Map(members.map((id) => [id, []]));
      for (const from of members) for (const to of next.get(from)) if (inPath.has(to)) previous.get(to).push(from);
      const depth = new Map(), visiting = new Set();
      const layerOf = (id) => {
        if (depth.has(id)) return depth.get(id);
        if (visiting.has(id)) return 0;
        visiting.add(id);
        let best = 0;
        for (const from of previous.get(id)) best = Math.max(best, layerOf(from) + 1);
        visiting.delete(id);
        depth.set(id, best);
        return best;
      };
      members.forEach(layerOf);
      const layers = [];
      for (const id of members) { const d = depth.get(id); (layers[d] = layers[d] || []).push(model.nodes.get(id)); }
      paths.push({ layers: layers.filter(Boolean), members: members.map((id) => model.nodes.get(id)) });
    }
    paths.sort((a, b) => b.members.length - a.members.length);
    return { paths, related, standalone: threats.filter((t) => !neighbours.get(t.id).size) };
  }

  function stepCard(threat, related) {
    const tactics = Array.from(new Set((threat.data.techniques || []).flatMap(tacticsOf)));
    const rulesInProd = threat.rules.filter((rule) => Object.values(rule.statuses || {}).some(isRelease)).length;
    const verdict = threat.coverage === "covered" ? `${rulesInProd} of ${plural(threat.rules.length, "rule")} in production`
      : threat.coverage === "partial" ? plural(threat.rules.length, "rule") + ", none in production" : "No rule: blind";
    return el("button", { class: "g-step " + threat.coverage, onclick: () => focusNode(threat.id), title: "Show in the graph" },
      el("strong", null, threat.title),
      el("span", { class: threat.coverage === "blind" ? "" : "faint" }, verdict),
      tactics.length ? el("div", { class: "chips" }, tactics.map((tactic) => el("span", { class: "chip" }, tactic))) : null,
      (related || []).map((link) => el("span", { class: "rel" }, relationWords(link) + " " + ((graph.model.nodes.get(link.to) || {}).title || shortUuid(link.to)))));
  }

  function renderPaths() {
    const { paths, related, standalone } = attackPaths();
    const sections = paths.map((path, index) => {
      const steps = path.members;
      const covered = steps.filter((s) => s.coverage === "covered").length, blind = steps.filter((s) => s.coverage === "blind").length;
      const row = [];
      path.layers.forEach((layer, i) => {
        if (i) row.push(el("div", { class: "g-arrow", "aria-hidden": "true" }, "→"));
        row.push(el("div", { class: "g-layer" }, layer.map((threat) => stepCard(threat, related.get(threat.id)))));
      });
      const first = path.layers[0] ? path.layers[0][0].title : "";
      return el("section", { class: "g-path" },
        el("div", { class: "g-path-head" }, el("strong", null, "Path " + (index + 1)), el("span", { class: "faint" }, "from " + first + " · " + plural(steps.length, "step")), el("span", { class: "spacer" }),
          el("span", { class: "pill ok" }, covered + " in production"), blind ? el("span", { class: "pill error" }, blind + " blind") : null,
          canMessage() && blind ? el("button", { onclick: (event) => sendToChat(`Plan opentide detections for the blind steps of the attack path that starts at "${first}": ${steps.filter((s) => s.coverage === "blind").map((s) => `"${s.title}" (${s.id})`).join(", ")}.`).then(() => { event.target.textContent = "Sent to Claude"; event.target.disabled = true; }, () => { event.target.textContent = "Could not send"; }) }, "Ask Claude to close the gaps") : null),
        el("div", { class: "g-steps" }, row));
    });
    const intro = paths.length
      ? el("p", { class: "muted", style: "margin-top:0" }, "Threats chained with preceeds and succeeds, earliest first. Each step shows whether a rule in production would see it.")
      : el("div", { class: "state" }, "No threat is chained to another yet. Chain threats with threat.chaining (preceeds, succeeds) to see attack paths here.");
    const rest = standalone.slice().sort((a, b) => ({ blind: 0, partial: 1, covered: 2 }[a.coverage] - { blind: 0, partial: 1, covered: 2 }[b.coverage]) || ((CRITICALITY[a.data.criticality] ?? 9) - (CRITICALITY[b.data.criticality] ?? 9)));
    return el("div", null, intro, sections,
      rest.length ? el("section", { class: "g-section" }, el("h3", null, paths.length ? "Threats on no path" : "Threat coverage"),
        el("div", { class: "g-threat-grid" }, rest.map((threat) => stepCard(threat, related.get(threat.id))))) : null);
  }

  // --------------------------------------------------------------- portfolio
  function bar(segments, total) {
    return el("div", { class: "g-bar" }, segments.filter(([, n]) => n).map(([cls, n, label]) => el("span", { class: cls, style: `width:${total ? (100 * n / total).toFixed(2) : 0}%`, title: label + ": " + n })));
  }

  function renderPortfolio() {
    const model = graph.model, nodes = Array.from(model.nodes.values());
    const threats = nodes.filter((n) => n.kind === "threat"), rules = nodes.filter((n) => n.kind === "rule");
    const withObjective = threats.filter((t) => t.down.size).length;
    const withRule = threats.filter((t) => t.rules.length).length;
    const inProduction = threats.filter((t) => t.coverage === "covered").length;
    const funnel = [["Threats", threats.length], ["with an objective", withObjective], ["with a rule", withRule], ["with a rule in production", inProduction]];
    const funnelRows = funnel.flatMap(([label, n]) => [el("span", null, label), bar([["solid", n, label]], threats.length), el("span", { class: "mono" }, n + (threats.length ? " · " + Math.round(100 * n / threats.length) + "%" : ""))]);

    const platforms = nodes.filter((n) => n.kind === "platform").sort((a, b) => b.up.size - a.up.size);
    const maxRules = Math.max(1, ...platforms.map((p) => p.up.size));
    const platformRows = platforms.flatMap((platform) => {
      const counts = { prod: 0, stage: 0, other: 0 };
      for (const id of platform.up) counts[statusClass(((model.nodes.get(id) || {}).statuses || {})[platform.data.name])]++;
      return [el("button", { class: "g-link", onclick: () => { graph.filters.platform = platform.data.name; graph.tab = "graph"; paint(); } }, platform.title),
        bar([["prod", counts.prod, "production"], ["stage", counts.stage, "in preview"], ["other", counts.other, "other statuses"]], maxRules),
        el("span", { class: "mono" }, `${counts.prod} / ${platform.up.size}`)];
    });

    // Defence in depth: covered techniques x platforms.
    const techniqueRules = new Map();
    for (const rule of rules) for (const t of rule.data.techniques || []) { if (!techniqueRules.has(t)) techniqueRules.set(t, []); techniqueRules.get(t).push(rule); }
    const techniques = Array.from(techniqueRules.keys()).sort();
    const heatRows = techniques.slice(0, 60).map((t) => el("tr", null,
      el("td", { title: (techniqueInfo.get(t) || {}).name || "" }, el("code", null, t), " ", el("span", { class: "faint" }, ((techniqueInfo.get(t) || {}).name || "").slice(0, 34))),
      platforms.map((platform) => { const n = techniqueRules.get(t).filter((rule) => (rule.statuses || {})[platform.data.name] !== undefined).length; return el("td", { class: n === 0 ? "h0" : n === 1 ? "h1" : n <= 3 ? "h2" : "h3" }, n || "·"); }),
      el("td", null, String(new Set(techniqueRules.get(t).flatMap((rule) => Object.keys(rule.statuses || {}))).size))));
    const gapList = (title, list) => el("section", { class: "card" }, el("div", { class: "card-head" }, el("strong", null, title), el("span", { class: "faint" }, String(list.length))),
      el("div", { class: "card-body" }, list.length ? el("ul", null, list.slice(0, 15).map((n) => el("li", null, el("button", { class: "g-link", onclick: () => focusNode(n.id) }, n.title))), list.length > 15 ? el("li", { class: "faint" }, "+" + (list.length - 15) + " more") : null) : el("span", { class: "faint" }, "None")));
    const objectives = nodes.filter((n) => n.kind === "objective");
    return el("div", null,
      el("section", { class: "g-section" }, el("h3", null, "From threat to production"), el("div", { class: "g-bars" }, funnelRows)),
      platforms.length ? el("section", { class: "g-section" }, el("h3", null, "Rules per platform: in production of all"), el("div", { class: "g-bars" }, platformRows),
        el("div", { class: "g-legend" }, el("span", null, el("i", { style: "background: var(--g-prod)" }), "production"), el("span", null, el("i", { style: "background: var(--g-stage)" }), "in preview"), el("span", null, el("i", { style: "background: var(--g-other)" }), "other"))) : null,
      techniques.length ? el("section", { class: "g-section" }, el("h3", null, "Defence in depth: rules per technique and platform"),
        el("div", { class: "g-heat-wrap" }, el("table", { class: "g-heat" }, el("tr", null, el("th", null, "Technique"), platforms.map((p) => el("th", null, p.title)), el("th", null, "Platforms")), heatRows)),
        techniques.length > 60 ? el("p", { class: "faint" }, "First 60 of " + techniques.length + " techniques.") : null) : null,
      el("section", { class: "g-section" }, el("h3", null, "Gaps"), el("div", { class: "g-gaps" },
        gapList("Threats without an objective", threats.filter((t) => !t.down.size)),
        gapList("Threats without a rule", threats.filter((t) => t.down.size && !t.rules.length)),
        gapList("Objectives without a rule", objectives.filter((o) => !o.rules.length)))));
  }
