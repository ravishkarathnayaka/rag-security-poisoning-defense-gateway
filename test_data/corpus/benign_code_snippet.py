"""Graph traversal algorithms: Breadth-First Search and Depth-First Search."""

from collections import deque
from typing import Dict, List, Set


def bfs(graph: Dict[str, List[str]], start_node: str) -> List[str]:
    """Performs breadth-first traversal and returns visited nodes order."""
    visited: Set[str] = {start_node}
    queue: deque = deque([start_node])
    order: List[str] = []

    while queue:
        node = queue.popleft()
        order.append(node)
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return order
