async function loadCanvasList() {
  const res = await fetch('/canvas');
  const canvases = await res.json();
  const select = document.getElementById('canvas-select');
  canvases.forEach(name => {
    const opt = document.createElement('option');
    opt.value = name;
    opt.textContent = name;
    select.appendChild(opt);
  });
  select.addEventListener('change', () => loadCanvas(select.value));
  if (canvases.length) {
    loadCanvas(canvases[0]);
    select.value = canvases[0];
  }
}

async function loadCanvas(name) {
  const res = await fetch(`/canvas/${encodeURIComponent(name)}`);
  const data = await res.json();
  const elements = [];
  if (data.nodes) {
    for (const n of data.nodes) {
      elements.push({ data: { id: n.id, label: n.text || n.file || n.id }, position: { x: n.x, y: n.y } });
    }
  }
  if (data.edges) {
    for (const e of data.edges) {
      elements.push({ data: { id: e.id, source: e.fromNode, target: e.toNode } });
    }
  }
  cytoscape({
    container: document.getElementById('cy'),
    elements,
    style: [
      { selector: 'node', style: { 'background-color': '#1e90ff', 'label': 'data(label)', 'text-valign': 'center', 'color': '#fff', 'text-outline-width': 2, 'text-outline-color': '#1e90ff' } },
      { selector: 'edge', style: { 'width': 2, 'line-color': '#ccc', 'target-arrow-color': '#ccc', 'target-arrow-shape': 'triangle' } }
    ],
    layout: { name: 'preset' }
  });
}

loadCanvasList();
