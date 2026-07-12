import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from analyzer import load_data, analyze_dependencies
from graph_engine import create_application_graph


st.set_page_config(
    page_title="ChainGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


st.markdown(
    """
    <style>
    .main-title {
        font-size: 60px;
        font-weight: 800;
        color: #172554;
        margin-bottom: 0;
    }

    .subtitle {
        color: #475569;
        font-size: 17px;
        margin-top: 0;
        margin-bottom: 25px;
    }

    .evidence-box {
        padding: 14px;
        border-radius: 10px;
        background-color: #eff6ff;
        border-left: 5px solid #2563eb;
        margin-bottom: 15px;
    }
    </style>
    """,
    unsafe_allow_html=True
)


def risk_level(score):
    """Convert an application score into a risk level."""

    if score >= 75:
        return "Critical"

    if score >= 50:
        return "High"

    if score >= 25:
        return "Medium"

    return "Low"


def build_application_summary(results):
    """Calculate one combined risk score for every application."""

    summary_rows = []

    for (
        app_id,
        app_name
    ), application_results in results.groupby(
        [
            "app_id",
            "app_name"
        ]
    ):

        confirmed = int(
            (
                application_results[
                    "vulnerability_status"
                ]
                == "confirmed"
            ).sum()
        )

        potential = int(
            (
                application_results[
                    "vulnerability_status"
                ]
                == "potential"
            ).sum()
        )

        licence_conflicts = int(
            (
                application_results[
                    "license_status"
                ]
                == "conflict"
            ).sum()
        )

        unmaintained = int(
            (
                application_results[
                    "maintenance_status"
                ]
                == "unmaintained"
            ).sum()
        )

        critical_findings = int(
            (
                application_results[
                    "severity"
                ]
                == "critical"
            ).sum()
        )

        maximum_dependency_score = float(
            application_results[
                "risk_score"
            ].max()
        )

        average_dependency_score = float(
            application_results[
                "risk_score"
            ].mean()
        )

        breadth_bonus = min(
            25,
            confirmed * 3
            + potential
            + licence_conflicts * 3
            + unmaintained
        )

        application_score = min(
            100,
            round(
                maximum_dependency_score
                + breadth_bonus,
                1
            )
        )

        summary_rows.append(
            {
                "app_id": app_id,
                "application": app_name,
                "dependencies": len(
                    application_results
                ),
                "confirmed_vulnerabilities": confirmed,
                "potential_vulnerabilities": potential,
                "licence_conflicts": licence_conflicts,
                "unmaintained_components": unmaintained,
                "critical_findings": critical_findings,
                "maximum_dependency_score": round(
                    maximum_dependency_score,
                    1
                ),
                "average_dependency_score": round(
                    average_dependency_score,
                    1
                ),
                "application_risk_score": application_score,
                "risk_level": risk_level(
                    application_score
                )
            }
        )

    summary = pd.DataFrame(
        summary_rows
    )

    return summary.sort_values(
        by="application_risk_score",
        ascending=False
    ).reset_index(
        drop=True
    )


def find_graph_source(
    dependency_graph,
    app_id,
    app_name
):
    """Find the application node inside the dependency graph."""

    possible_sources = [
        app_name,
        app_id,
        f"APP::{app_id}",
        f"Application: {app_name}"
    ]

    for source in possible_sources:

        if source in dependency_graph:
            return source

    matching_nodes = [
        node
        for node in dependency_graph.nodes
        if app_name.lower()
        in str(node).lower()
        or app_id.lower()
        in str(node).lower()
    ]

    if matching_nodes:
        return matching_nodes[0]

    root_nodes = [
        node
        for node in dependency_graph.nodes
        if dependency_graph.in_degree(
            node
        )
        == 0
    ]

    if root_nodes:

        return max(
            root_nodes,
            key=lambda node: len(
                nx.descendants(
                    dependency_graph,
                    node
                )
            )
        )

    return None


def create_attack_path_figure(
    dependency_graph,
    source_node,
    risky_results
):
    """Create a focused attack-path dependency graph."""

    if source_node is None:
        return None, 0

    risky_results = risky_results.sort_values(
        by="risk_score",
        ascending=False
    )

    risky_results = risky_results.drop_duplicates(
        subset=[
            "component"
        ]
    ).head(12)

    path_nodes = set()
    path_edges = set()
    resolved_targets = 0

    for _, finding in risky_results.iterrows():

        target = finding[
            "component"
        ]

        if target not in dependency_graph:
            continue

        try:
            path = nx.shortest_path(
                dependency_graph,
                source=source_node,
                target=target
            )

            resolved_targets += 1
            path_nodes.update(path)

            for index in range(
                len(path) - 1
            ):
                path_edges.add(
                    (
                        path[index],
                        path[index + 1]
                    )
                )

        except (
            nx.NetworkXNoPath,
            nx.NodeNotFound
        ):
            continue

    if not path_nodes:
        return None, 0

    attack_graph = dependency_graph.subgraph(
        path_nodes
    ).copy()

    position = nx.spring_layout(
        attack_graph,
        seed=42,
        k=1.5
    )

    edge_x = []
    edge_y = []

    for source, target in path_edges:

        if (
            source not in position
            or target not in position
        ):
            continue

        source_x, source_y = position[
            source
        ]

        target_x, target_y = position[
            target
        ]

        edge_x.extend(
            [
                source_x,
                target_x,
                None
            ]
        )

        edge_y.extend(
            [
                source_y,
                target_y,
                None
            ]
        )

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line={
            "width": 1.8,
            "color": "#94a3b8"
        },
        hoverinfo="none",
        name="Dependency relationship"
    )

    node_x = []
    node_y = []
    node_text = []
    node_hover = []
    node_colours = []
    node_sizes = []

    component_findings = (
        risky_results
        .drop_duplicates(
            subset=[
                "component"
            ]
        )
        .set_index(
            "component"
        )
        .to_dict(
            orient="index"
        )
    )

    for node in attack_graph.nodes:

        x_value, y_value = position[
            node
        ]

        node_x.append(
            x_value
        )

        node_y.append(
            y_value
        )

        node_text.append(
            str(node)
        )

        if node == source_node:

            node_colours.append(
                "#1e3a8a"
            )

            node_sizes.append(
                34
            )

            node_hover.append(
                f"Application: {node}"
            )

        elif node in component_findings:

            finding = component_findings[
                node
            ]

            vulnerability_status = finding.get(
                "vulnerability_status",
                "none"
            )

            licence_status = finding.get(
                "license_status",
                "compatible"
            )

            maintenance_status = finding.get(
                "maintenance_status",
                "maintained"
            )

            if vulnerability_status == "confirmed":

                colour = "#dc2626"
                finding_type = (
                    "Confirmed vulnerability"
                )

            elif vulnerability_status == "potential":

                colour = "#f97316"
                finding_type = (
                    "Potential vulnerability"
                )

            elif licence_status == "conflict":

                colour = "#9333ea"
                finding_type = (
                    "Licence conflict"
                )

            elif maintenance_status == "unmaintained":

                colour = "#eab308"
                finding_type = (
                    "Unmaintained component"
                )

            else:

                colour = "#0ea5e9"
                finding_type = (
                    "Risky dependency"
                )

            node_colours.append(
                colour
            )

            node_sizes.append(
                28
            )

            node_hover.append(
                f"Component: {node}"
                f"<br>Finding: {finding_type}"
                f"<br>Version: {finding.get('version', 'Unknown')}"
                f"<br>Risk score: {finding.get('risk_score', 0)}"
                f"<br>CVEs: {finding.get('cve_ids', 'No CVE')}"
            )

        else:

            node_colours.append(
                "#38bdf8"
            )

            node_sizes.append(
                20
            )

            node_hover.append(
                f"Dependency: {node}"
            )

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=node_text,
        textposition="top center",
        hovertext=node_hover,
        hoverinfo="text",
        marker={
            "size": node_sizes,
            "color": node_colours,
            "line": {
                "width": 2,
                "color": "white"
            }
        },
        name="Components"
    )

    figure = go.Figure(
        data=[
            edge_trace,
            node_trace
        ]
    )

    figure.update_layout(
        title=(
            "Application → Dependency → Risk"
        ),
        showlegend=False,
        hovermode="closest",
        height=620,
        margin={
            "l": 20,
            "r": 20,
            "t": 60,
            "b": 20
        },
        xaxis={
            "showgrid": False,
            "zeroline": False,
            "showticklabels": False
        },
        yaxis={
            "showgrid": False,
            "zeroline": False,
            "showticklabels": False
        },
        plot_bgcolor="white",
        paper_bgcolor="white"
    )

    return figure, resolved_targets


try:
    data = load_data()

    results = analyze_dependencies(
        data
    )

    application_summary = (
        build_application_summary(
            results
        )
    )

    st.markdown(
        '<p class="main-title">🛡️ ChainGuard</p>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<p class="subtitle">'
        'Graph-Based Software Supply Chain Risk Intelligence'
        '</p>',
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div class="evidence-box">
        <b>Evidence-aware analysis:</b>
        ChainGuard separates exact affected-version matches
        from libraries that only require further version
        verification. This reduces misleading vulnerability
        claims.
        </div>
        """,
        unsafe_allow_html=True
    )

    confirmed_count = int(
        (
            results[
                "vulnerability_status"
            ]
            == "confirmed"
        ).sum()
    )

    potential_count = int(
        (
            results[
                "vulnerability_status"
            ]
            == "potential"
        ).sum()
    )

    licence_conflicts = int(
        (
            results[
                "license_status"
            ]
            == "conflict"
        ).sum()
    )

    unmaintained_count = int(
        (
            results[
                "maintenance_status"
            ]
            == "unmaintained"
        ).sum()
    )

    critical_count = int(
        (
            results[
                "severity"
            ]
            == "critical"
        ).sum()
    )

    metric1, metric2, metric3, metric4, metric5 = (
        st.columns(5)
    )

    metric1.metric(
        "Confirmed Vulnerabilities",
        confirmed_count
    )

    metric2.metric(
        "Potential Vulnerabilities",
        potential_count
    )

    metric3.metric(
        "Licence Conflicts",
        licence_conflicts
    )

    metric4.metric(
        "Unmaintained Components",
        unmaintained_count
    )

    metric5.metric(
        "Critical Findings",
        critical_count
    )

    st.sidebar.title(
        "Dashboard Filters"
    )

    application_options = [
        "All Applications"
    ] + application_summary[
        "application"
    ].tolist()

    selected_application = (
        st.sidebar.selectbox(
            "Application",
            application_options
        )
    )

    severity_options = [
        "All Severities",
        "critical",
        "high",
        "medium",
        "low"
    ]

    selected_severity = (
        st.sidebar.selectbox(
            "Severity",
            severity_options
        )
    )

    evidence_options = [
        "All Evidence",
        "confirmed",
        "potential",
        "none"
    ]

    selected_evidence = (
        st.sidebar.selectbox(
            "Vulnerability evidence",
            evidence_options
        )
    )

    filtered_results = results.copy()

    if (
        selected_application
        != "All Applications"
    ):

        filtered_results = filtered_results[
            filtered_results[
                "app_name"
            ]
            == selected_application
        ]

    if (
        selected_severity
        != "All Severities"
    ):

        filtered_results = filtered_results[
            filtered_results[
                "severity"
            ]
            == selected_severity
        ]

    if (
        selected_evidence
        != "All Evidence"
    ):

        filtered_results = filtered_results[
            filtered_results[
                "vulnerability_status"
            ]
            == selected_evidence
        ]

    overview_tab, ranking_tab, findings_tab, graph_tab, inventory_tab = (
        st.tabs(
            [
                "Executive Overview",
                "Application Ranking",
                "Risk Findings",
                "Attack Paths",
                "Data Inventory"
            ]
        )
    )

    with overview_tab:

        st.header(
            "Organisation Risk Overview"
        )

        chart_data = (
            application_summary.sort_values(
                by="application_risk_score",
                ascending=True
            )
        )

        risk_chart = px.bar(
            chart_data,
            x="application_risk_score",
            y="application",
            orientation="h",
            color="risk_level",
            color_discrete_map={
                "Critical": "#dc2626",
                "High": "#f97316",
                "Medium": "#eab308",
                "Low": "#22c55e"
            },
            labels={
                "application_risk_score":
                    "Application Risk Score",
                "application":
                    "Application",
                "risk_level":
                    "Risk Level"
            },
            title=(
                "Applications Ranked by Supply Chain Risk"
            )
        )

        risk_chart.update_layout(
            height=520,
            margin={
                "l": 20,
                "r": 20,
                "t": 60,
                "b": 20
            }
        )

        st.plotly_chart(
            risk_chart,
            width="stretch"
        )

        highest_risk_application = (
            application_summary.iloc[0]
        )

        st.error(
            f"Highest priority: "
            f"{highest_risk_application['application']} "
            f"has an application risk score of "
            f"{highest_risk_application['application_risk_score']}/100."
        )

        st.subheader(
            "Recommended Remediation Priority"
        )

        highest_findings = results.sort_values(
            by="risk_score",
            ascending=False
        ).head(10)

        remediation_columns = [
            "app_name",
            "component",
            "version",
            "vulnerability_status",
            "cve_ids",
            "license_status",
            "maintenance_status",
            "patched_versions",
            "risk_score",
            "severity"
        ]

        available_remediation_columns = [
            column
            for column in remediation_columns
            if column in highest_findings.columns
        ]

        st.dataframe(
            highest_findings[
                available_remediation_columns
            ],
            width="stretch",
            hide_index=True
        )

    with ranking_tab:

        st.header(
            "Ranked Application Risk Report"
        )

        st.write(
            "The score combines the most serious dependency "
            "risk with the number of vulnerabilities, licence "
            "conflicts and unmaintained components."
        )

        st.dataframe(
            application_summary,
            width="stretch",
            hide_index=True
        )

        st.download_button(
            "Download Application Risk Report",
            data=application_summary.to_csv(
                index=False
            ),
            file_name=(
                "chainguard_application_risk_report.csv"
            ),
            mime="text/csv"
        )

    with findings_tab:

        st.header(
            "Dependency-Level Risk Findings"
        )

        st.write(
            f"Showing {len(filtered_results)} findings "
            "after applying the sidebar filters."
        )

        findings_columns = [
            "app_name",
            "parent_component",
            "component",
            "version",
            "direct",
            "dependency_depth",
            "vulnerability_status",
            "version_evidence",
            "cve_ids",
            "patched_versions",
            "license",
            "license_status",
            "maintenance_status",
            "risk_score",
            "severity",
            "explanation"
        ]

        available_findings_columns = [
            column
            for column in findings_columns
            if column in filtered_results.columns
        ]

        displayed_findings = (
            filtered_results.sort_values(
                by="risk_score",
                ascending=False
            )
        )

        st.dataframe(
            displayed_findings[
                available_findings_columns
            ],
            width="stretch",
            hide_index=True
        )

        st.download_button(
            "Download Filtered Findings",
            data=displayed_findings.to_csv(
                index=False
            ),
            file_name=(
                "chainguard_dependency_findings.csv"
            ),
            mime="text/csv"
        )

    with graph_tab:

        st.header(
            "Attack Path Visualisation"
        )

        graph_application = (
            st.selectbox(
                "Select an application to inspect",
                application_summary[
                    "application"
                ].tolist(),
                key="attack_path_application"
            )
        )

        selected_summary = (
            application_summary[
                application_summary[
                    "application"
                ]
                == graph_application
            ].iloc[0]
        )

        selected_app_id = (
            selected_summary[
                "app_id"
            ]
        )

        selected_app_results = results[
            results[
                "app_id"
            ]
            == selected_app_id
        ].copy()

        risky_app_results = (
            selected_app_results[
                (
                    selected_app_results[
                        "vulnerability_status"
                    ]
                    != "none"
                )
                |
                (
                    selected_app_results[
                        "license_status"
                    ]
                    == "conflict"
                )
                |
                (
                    selected_app_results[
                        "maintenance_status"
                    ]
                    == "unmaintained"
                )
                |
                (
                    selected_app_results[
                        "risk_score"
                    ]
                    >= 50
                )
            ]
        )

        if risky_app_results.empty:

            st.success(
                "No major attack paths were identified "
                "for this application."
            )

        else:

            try:
                dependency_graph = (
                    create_application_graph(
                        data[
                            "dependencies"
                        ],
                        selected_app_id
                    )
                )

                source_node = find_graph_source(
                    dependency_graph,
                    selected_app_id,
                    graph_application
                )

                attack_figure, resolved_targets = (
                    create_attack_path_figure(
                        dependency_graph,
                        source_node,
                        risky_app_results
                    )
                )

                if attack_figure is None:

                    st.warning(
                        "Risky components were identified, but "
                        "a complete path from the application "
                        "could not be visualised."
                    )

                else:

                    st.plotly_chart(
                        attack_figure,
                        width="stretch"
                    )

                    st.caption(
                        f"{resolved_targets} high-priority "
                        "risk paths are displayed."
                    )

                    st.markdown(
                        """
                        **Graph colours**

                        - Dark blue: Application
                        - Red: Confirmed vulnerability
                        - Orange: Potential vulnerability
                        - Purple: Licence conflict
                        - Yellow: Unmaintained component
                        - Light blue: Dependency in the attack path
                        """
                    )

            except Exception as graph_error:

                st.warning(
                    f"Attack-path graph could not be created: "
                    f"{graph_error}"
                )

        st.subheader(
            "Attack Path Evidence"
        )

        attack_path_columns = [
            "parent_component",
            "component",
            "version",
            "direct",
            "dependency_depth",
            "vulnerability_status",
            "cve_ids",
            "license_status",
            "maintenance_status",
            "risk_score",
            "explanation"
        ]

        available_attack_columns = [
            column
            for column in attack_path_columns
            if column in risky_app_results.columns
        ]

        st.dataframe(
            risky_app_results.sort_values(
                by="risk_score",
                ascending=False
            )[
                available_attack_columns
            ],
            width="stretch",
            hide_index=True
        )

    with inventory_tab:

        st.header(
            "Official Dataset Inventory"
        )

        inventory1, inventory2, inventory3 = (
            st.columns(3)
        )

        inventory1.metric(
            "Applications",
            len(
                data[
                    "applications"
                ]
            )
        )

        inventory2.metric(
            "SBOM Dependencies",
            len(
                data[
                    "dependencies"
                ]
            )
        )

        inventory3.metric(
            "Vulnerability Records",
            len(
                data[
                    "vulnerabilities"
                ]
            )
        )

        inventory4, inventory5, inventory6 = (
            st.columns(3)
        )

        inventory4.metric(
            "Licence Rules",
            len(
                data[
                    "license_rules"
                ]
            )
        )

        inventory5.metric(
            "Transitive Relationships",
            len(
                data.get(
                    "transitive_dependencies",
                    []
                )
            )
        )

        inventory6.metric(
            "Ground-Truth Labels",
            len(
                data.get(
                    "labels",
                    []
                )
            )
        )

        st.subheader(
            "Applications"
        )

        st.dataframe(
            data[
                "applications"
            ],
            width="stretch",
            hide_index=True
        )


except FileNotFoundError as error:

    st.error(
        f"Required dataset file was not found: {error}"
    )

    st.info(
        "Check that all six official files are inside "
        "the official_data folder."
    )


except Exception as error:

    st.error(
        f"Unable to load the ChainGuard dashboard: {error}"
    )