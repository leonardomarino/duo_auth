# Graph Report - .  (2026-04-11)

## Corpus Check
- 4 files · ~0 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 86 nodes · 120 edges · 8 communities detected
- Extraction: 68% EXTRACTED · 32% INFERRED · 0% AMBIGUOUS · INFERRED: 38 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## God Nodes (most connected - your core abstractions)
1. `DuoAuthTest` - 21 edges
2. `duo_auth` - 20 edges
3. `rcube_plugin` - 7 edges
4. `rcube_utils` - 6 edges
5. `rcube` - 5 edges
6. `rcube_session` - 5 edges
7. `rcube_config` - 4 edges
8. `rcube_output` - 4 edges
9. `rcube_user` - 4 edges
10. `DuoAuthTestHelper` - 4 edges

## Surprising Connections (you probably didn't know these)
- None detected - all connections are within the same source files.

## Communities

### Community 0 - "Community 0"
Cohesion: 0.09
Nodes (1): DuoAuthTest

### Community 1 - "Community 1"
Cohesion: 0.27
Nodes (1): duo_auth

### Community 2 - "Community 2"
Cohesion: 0.12
Nodes (4): DuoAuthTestRedirectException, rcube_output, rcube_user, rcube_utils

### Community 3 - "Community 3"
Cohesion: 0.25
Nodes (2): DuoAuthTestHelper, rcube_config

### Community 4 - "Community 4"
Cohesion: 0.29
Nodes (1): rcube_plugin

### Community 5 - "Community 5"
Cohesion: 0.4
Nodes (1): rcube

### Community 6 - "Community 6"
Cohesion: 0.4
Nodes (1): rcube_session

### Community 7 - "Community 7"
Cohesion: 1.0
Nodes (0): 

## Knowledge Gaps
- **Thin community `Community 7`** (1 nodes): `install.php`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `rcube_plugin` connect `Community 4` to `Community 2`?**
  _High betweenness centrality (0.063) - this node is a cross-community bridge._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.09 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.12 - nodes in this community are weakly interconnected._