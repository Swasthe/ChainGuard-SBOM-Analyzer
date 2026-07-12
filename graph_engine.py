import json
from pathlib import Path

import networkx as nx
import pandas as pd


DATA_FOLDER = (
    Path(__file__).parent
    / "official_data"
)


def load_transitive_dependencies():
    """Load the official transitive dependency edges."""

    file_path = (
        DATA_FOLDER
        / "transitive_dependencies.json"
    )

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:

        return pd.DataFrame(
            json.load(file)
        )


def create_application_graph(
    dependencies,
    app_id
):
    """
    Build:
    Application → direct dependency
                → transitive dependency
    """

    app_dependencies = dependencies[
        dependencies["app_id"]
        == app_id
    ].copy()

    graph = nx.DiGraph()

    if app_dependencies.empty:
        return graph

    application_name = str(
        app_dependencies.iloc[0][
            "app_name"
        ]
    )

    # Add the application root
    graph.add_node(
        application_name,
        node_type="application",
        version="",
        license="",
        risk_type="application"
    )

    # Create component metadata lookup
    component_lookup = {}

    for _, dependency in (
        app_dependencies.iterrows()
    ):

        component = str(
            dependency["component"]
        )

        component_lookup[component] = {
            "version": str(
                dependency["version"]
            ),
            "license": str(
                dependency["license"]
            ),
            "direct": str(
                dependency["direct"]
            )
        }

        graph.add_node(
            component,
            node_type="dependency",
            version=str(
                dependency["version"]
            ),
            license=str(
                dependency["license"]
            ),
            direct=str(
                dependency["direct"]
            )
        )

    # Add application → direct dependency edges
    direct_dependencies = app_dependencies[
        app_dependencies["direct"]
        .astype(str)
        .str.lower()
        == "yes"
    ]

    for _, dependency in (
        direct_dependencies.iterrows()
    ):

        component = str(
            dependency["component"]
        )

        graph.add_edge(
            application_name,
            component,
            edge_type="direct"
        )

    # Add every official parent → child edge
    transitive_dependencies = (
        load_transitive_dependencies()
    )

    app_transitive = (
        transitive_dependencies[
            transitive_dependencies[
                "application_id"
            ]
            == app_id
        ]
    )

    for _, relationship in (
        app_transitive.iterrows()
    ):

        parent = str(
            relationship[
                "parent_library"
            ]
        )

        child = str(
            relationship[
                "child_library"
            ]
        )

        parent_version = str(
            relationship[
                "parent_version"
            ]
        )

        child_version = str(
            relationship[
                "child_version"
            ]
        )

        # Add parent if it is not already present
        if parent not in graph:

            parent_metadata = (
                component_lookup.get(
                    parent,
                    {}
                )
            )

            graph.add_node(
                parent,
                node_type="dependency",
                version=parent_metadata.get(
                    "version",
                    parent_version
                ),
                license=parent_metadata.get(
                    "license",
                    "Unknown"
                ),
                direct=parent_metadata.get(
                    "direct",
                    "no"
                )
            )

        # Add child if it is not already present
        if child not in graph:

            child_metadata = (
                component_lookup.get(
                    child,
                    {}
                )
            )

            graph.add_node(
                child,
                node_type="dependency",
                version=child_metadata.get(
                    "version",
                    child_version
                ),
                license=child_metadata.get(
                    "license",
                    "Unknown"
                ),
                direct=child_metadata.get(
                    "direct",
                    "no"
                )
            )

        graph.add_edge(
            parent,
            child,
            edge_type="transitive"
        )

    return graph


def find_dependency_paths(
    graph,
    application_name,
    target_component,
    maximum_depth=8
):
    """Find all paths to a selected dependency."""

    if application_name not in graph:
        return []

    if target_component not in graph:
        return []

    try:
        paths = list(
            nx.all_simple_paths(
                graph,
                source=application_name,
                target=target_component,
                cutoff=maximum_depth
            )
        )

        return paths

    except nx.NetworkXError:
        return []


def graph_summary(graph):
    """Return useful graph statistics."""

    direct_edges = sum(
        1
        for _, _, data in graph.edges(
            data=True
        )
        if data.get("edge_type")
        == "direct"
    )

    transitive_edges = sum(
        1
        for _, _, data in graph.edges(
            data=True
        )
        if data.get("edge_type")
        == "transitive"
    )

    return {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "direct_edges": direct_edges,
        "transitive_edges": transitive_edges,
        "is_dag": nx.is_directed_acyclic_graph(
            graph
        )
    }


if __name__ == "__main__":

    from analyzer import load_data

    data = load_data()

    applications = data[
        "applications"
    ]

    dependencies = data[
        "dependencies"
    ]

    first_application = (
        applications.iloc[0]
    )

    graph = create_application_graph(
        dependencies,
        first_application[
            "app_id"
        ]
    )

    summary = graph_summary(
        graph
    )

    print(
        "Official dependency graph created."
    )

    print(
        "Application:",
        first_application[
            "app_name"
        ]
    )

    print(
        "Nodes:",
        summary["nodes"]
    )

    print(
        "Edges:",
        summary["edges"]
    )

    print(
        "Direct edges:",
        summary["direct_edges"]
    )

    print(
        "Transitive edges:",
        summary[
            "transitive_edges"
        ]
    )

    print(
        "Acyclic graph:",
        summary["is_dag"]
    )