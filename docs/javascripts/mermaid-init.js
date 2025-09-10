// Initialize Mermaid rendering for MkDocs Material
document$.subscribe(() => {
  if (window.mermaid) {
    mermaid.initialize({ startOnLoad: false, theme: 'default' });
    mermaid.run();
  }
});

