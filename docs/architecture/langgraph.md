---
title: Langgraph Architecture
---

# Description

The flow uses a fan-out/fan-in pattern. `init_file_path` validates the input and seeds shared state, then triggers two parallel branches: `static_agent` (static triage—metadata, hashes, YARA/CAPA) and `cti_analysis` (threat-intel enrichment via hash/IOC lookups). A `supervisor` node merges results, deduplicates and reconciles evidence, assigns confidence, and outputs a single structured JSON summary.


## Langgraph Architecture

```mermaid
---
config:
  flowchart:
    curve: linear
---
graph TD;
	__start__([<p>__start__</p>]):::first
	init_file_path(init_file_path)
	static_agent(static_agent)
	cti_analysis(cti_analysis)
	supervisor(supervisor)
	__end__([<p>__end__</p>]):::last
	__start__ --> init_file_path;
	cti_analysis --> supervisor;
	init_file_path --> cti_analysis;
	init_file_path --> static_agent;
	static_agent --> supervisor;
	supervisor --> __end__;
```