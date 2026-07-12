import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from analyzer import (
    load_data,
    analyze_dependencies
)

from graph_engine import (
    create_application_graph
)


st.set_page_config(
    page_title="Performance Evaluation",
    page_icon="📊",
    layout="wide"
)

st.title("Official Performance Evaluation")

st.write(
    "Compare strict confirmed detection with "
    "broader potential-risk screening."
)


def calculate_metrics(
    expected,
    predicted
):
    """Calculate binary classification metrics."""

    expected = expected.astype(bool)
    predicted = predicted.astype(bool)

    true_positive = int(
        (
            expected
            & predicted
        ).sum()
    )

    true_negative = int(
        (
            ~expected
            & ~predicted
        ).sum()
    )

    false_positive = int(
        (
            ~expected
            & predicted
        ).sum()
    )

    false_negative = int(
        (
            expected
            & ~predicted
        ).sum()
    )

    precision = (
        true_positive
        / (
            true_positive
            + false_positive
        )
        if (
            true_positive
            + false_positive
        ) > 0
        else 0
    )

    recall = (
        true_positive
        / (
            true_positive
            + false_negative
        )
        if (
            true_positive
            + false_negative
        ) > 0
        else 0
    )

    false_positive_rate = (
        false_positive
        / (
            false_positive
            + true_negative
        )
        if (
            false_positive
            + true_negative
        ) > 0
        else 0
    )

    f1_score = (
        2
        * precision
        * recall
        / (
            precision
            + recall
        )
        if (
            precision
            + recall
        ) > 0
        else 0
    )

    accuracy = (
        true_positive
        + true_negative
    ) / max(
        true_positive
        + true_negative
        + false_positive
        + false_negative,
        1
    )

    return {
        "TP": true_positive,
        "TN": true_negative,
        "FP": false_positive,
        "FN": false_negative,
        "precision": precision,
        "recall": recall,
        "fpr": false_positive_rate,
        "f1": f1_score,
        "accuracy": accuracy
    }


def create_confusion_matrix(
    metrics,
    title
):
    """Create a confusion-matrix heatmap."""

    values = [
        [
            metrics["TN"],
            metrics["FP"]
        ],
        [
            metrics["FN"],
            metrics["TP"]
        ]
    ]

    figure = go.Figure(
        data=go.Heatmap(
            z=values,
            x=[
                "Predicted Clean",
                "Predicted Risk"
            ],
            y=[
                "Actually Clean",
                "Actually Risk"
            ],
            text=values,
            texttemplate="%{text}",
            colorscale="Blues",
            showscale=False
        )
    )

    figure.update_layout(
        title=title,
        height=400
    )

    return figure


def calculate_transitive_coverage(data):
    """Check official transitive-edge coverage."""

    dependencies = data[
        "dependencies"
    ]

    applications = data[
        "applications"
    ]

    transitive = data[
        "transitive"
    ]

    graph_lookup = {}

    for _, application in applications.iterrows():

        app_id = application[
            "app_id"
        ]

        graph_lookup[app_id] = (
            create_application_graph(
                dependencies,
                app_id
            )
        )

    resolved_edges = 0

    for _, edge in transitive.iterrows():

        graph = graph_lookup.get(
            edge["application_id"]
        )

        if graph is None:
            continue

        parent = str(
            edge["parent_library"]
        )

        child = str(
            edge["child_library"]
        )

        if graph.has_edge(
            parent,
            child
        ):

            resolved_edges += 1

    total_edges = len(
        transitive
    )

    coverage = (
        resolved_edges / total_edges
        if total_edges > 0
        else 0
    )

    return (
        resolved_edges,
        total_edges,
        coverage
    )


try:
    data = load_data()

    results = analyze_dependencies(
        data
    )

    labels = data[
        "labels"
    ]

    evaluation = results.merge(
        labels,
        left_on="dependency_id",
        right_on="dep_id",
        how="inner",
        suffixes=(
            "_detected",
            "_expected"
        )
    )

    if evaluation.empty:

        st.error(
            "No predictions matched the "
            "official ground-truth labels."
        )

        st.stop()

    expected_risky = (
        evaluation["is_risky"]
        .astype(str)
        .str.lower()
        == "true"
    )

    expected_vulnerability = (
        evaluation["risk_type"]
        .astype(str)
        .str.contains(
            "VULNER",
            case=False,
            na=False
        )
    )

    expected_licence = (
        evaluation["risk_type"]
        .astype(str)
        .str.contains(
            "LICENSE",
            case=False,
            na=False
        )
    )

    expected_maintenance = (
        evaluation["risk_type"]
        .astype(str)
        .str.upper()
        == "UNMAINTAINED"
    )

    strict_vulnerability = (
        evaluation[
            "vulnerability_status"
        ]
        == "confirmed"
    )

    screening_vulnerability = (
        evaluation[
            "vulnerability_status"
        ].isin(
            [
                "confirmed",
                "potential"
            ]
        )
    )

    licence_prediction = (
        evaluation[
            "license_status"
        ].isin(
            [
                "conflict",
                "unknown"
            ]
        )
    )

    maintenance_prediction = (
        evaluation[
            "maintenance_status"
        ]
        == "unmaintained"
    )

    strict_overall = (
        strict_vulnerability
        | licence_prediction
        | maintenance_prediction
    )

    screening_overall = (
        screening_vulnerability
        | licence_prediction
        | maintenance_prediction
    )

    strict_vulnerability_metrics = (
        calculate_metrics(
            expected_vulnerability,
            strict_vulnerability
        )
    )

    screening_vulnerability_metrics = (
        calculate_metrics(
            expected_vulnerability,
            screening_vulnerability
        )
    )

    strict_overall_metrics = (
        calculate_metrics(
            expected_risky,
            strict_overall
        )
    )

    screening_overall_metrics = (
        calculate_metrics(
            expected_risky,
            screening_overall
        )
    )

    licence_metrics = calculate_metrics(
        expected_licence,
        licence_prediction
    )

    maintenance_metrics = (
        calculate_metrics(
            expected_maintenance,
            maintenance_prediction
        )
    )

    (
        resolved_edges,
        total_edges,
        transitive_coverage
    ) = calculate_transitive_coverage(
        data
    )

    # -------------------------------------
    # EVIDENCE MODES
    # -------------------------------------

    st.header("Vulnerability Evidence Modes")

    strict_column, screening_column = (
        st.columns(2)
    )

    with strict_column:

        st.subheader(
            "Strict Confirmed Mode"
        )

        st.metric(
            "Vulnerability Recall",
            (
                f"{strict_vulnerability_metrics['recall'] * 100:.1f}%"
            )
        )

        st.metric(
            "False-Positive Rate",
            (
                f"{strict_vulnerability_metrics['fpr'] * 100:.1f}%"
            )
        )

        st.write(
            "Requires the installed version to "
            "appear inside affected_versions."
        )

    with screening_column:

        st.subheader(
            "Potential Screening Mode"
        )

        st.metric(
            "Vulnerability Recall",
            (
                f"{screening_vulnerability_metrics['recall'] * 100:.1f}%"
            )
        )

        st.metric(
            "False-Positive Rate",
            (
                f"{screening_vulnerability_metrics['fpr'] * 100:.1f}%"
            )
        )

        st.write(
            "Flags libraries with known CVEs even "
            "when the installed version is absent "
            "from affected_versions."
        )

    st.warning(
        "The official vulnerability labels do not "
        "agree with affected_versions. Strict mode "
        "avoids unsupported claims. Screening mode "
        "reduces missed risks but increases false alerts."
    )

    st.divider()

    # -------------------------------------
    # SUCCESS CRITERIA
    # -------------------------------------

    st.header("Official Success Criteria")

    result1, result2, result3 = (
        st.columns(3)
    )

    result1.metric(
        "Screening Vulnerability Recall",
        (
            f"{screening_vulnerability_metrics['recall'] * 100:.1f}%"
        ),
        "Target: >85%"
    )

    result2.metric(
        "Transitive Resolution",
        (
            f"{transitive_coverage * 100:.1f}%"
        ),
        "Target: 100%"
    )

    result3.metric(
        "Licence Conflict Recall",
        (
            f"{licence_metrics['recall'] * 100:.1f}%"
        ),
        "Target: >90%"
    )

    result4, result5, result6 = (
        st.columns(3)
    )

    result4.metric(
        "Strict Overall Precision",
        (
            f"{strict_overall_metrics['precision'] * 100:.1f}%"
        )
    )

    result5.metric(
        "Screening Overall Recall",
        (
            f"{screening_overall_metrics['recall'] * 100:.1f}%"
        )
    )

    result6.metric(
        "Screening False-Positive Rate",
        (
            f"{screening_overall_metrics['fpr'] * 100:.1f}%"
        ),
        "Target: <20%"
    )

    st.caption(
        f"Resolved {resolved_edges} of "
        f"{total_edges} official transitive edges."
    )

    st.divider()

    # -------------------------------------
    # CATEGORY TABLE
    # -------------------------------------

    st.header("Category-Level Evaluation")

    category_results = pd.DataFrame(
        [
            {
                "Category":
                    "Strict vulnerability",
                "Expected cases":
                    int(
                        expected_vulnerability.sum()
                    ),
                "Precision":
                    strict_vulnerability_metrics[
                        "precision"
                    ],
                "Recall":
                    strict_vulnerability_metrics[
                        "recall"
                    ],
                "False-positive rate":
                    strict_vulnerability_metrics[
                        "fpr"
                    ]
            },
            {
                "Category":
                    "Potential screening",
                "Expected cases":
                    int(
                        expected_vulnerability.sum()
                    ),
                "Precision":
                    screening_vulnerability_metrics[
                        "precision"
                    ],
                "Recall":
                    screening_vulnerability_metrics[
                        "recall"
                    ],
                "False-positive rate":
                    screening_vulnerability_metrics[
                        "fpr"
                    ]
            },
            {
                "Category":
                    "Licence conflicts",
                "Expected cases":
                    int(
                        expected_licence.sum()
                    ),
                "Precision":
                    licence_metrics[
                        "precision"
                    ],
                "Recall":
                    licence_metrics[
                        "recall"
                    ],
                "False-positive rate":
                    licence_metrics[
                        "fpr"
                    ]
            },
            {
                "Category":
                    "Maintenance",
                "Expected cases":
                    int(
                        expected_maintenance.sum()
                    ),
                "Precision":
                    maintenance_metrics[
                        "precision"
                    ],
                "Recall":
                    maintenance_metrics[
                        "recall"
                    ],
                "False-positive rate":
                    maintenance_metrics[
                        "fpr"
                    ]
            }
        ]
    )

    for column in [
        "Precision",
        "Recall",
        "False-positive rate"
    ]:

        category_results[column] = (
            category_results[column].map(
                lambda value:
                    f"{value * 100:.1f}%"
            )
        )

    st.dataframe(
        category_results,
        width="stretch",
        hide_index=True
    )

    st.divider()

    # -------------------------------------
    # CONFUSION MATRICES
    # -------------------------------------

    st.header("Overall Confusion Matrices")

    matrix1, matrix2 = st.columns(2)

    with matrix1:

        st.plotly_chart(
            create_confusion_matrix(
                strict_overall_metrics,
                "Strict Mode"
            ),
            width="stretch"
        )

    with matrix2:

        st.plotly_chart(
            create_confusion_matrix(
                screening_overall_metrics,
                "Screening Mode"
            ),
            width="stretch"
        )

    st.info(
        "The official labels contain severity "
        "categories but no numeric expected risk "
        "scores. Numeric ±10 score accuracy cannot "
        "be calculated directly."
    )


except Exception as error:

    st.error(
        "Unable to evaluate the official "
        f"dataset: {error}"
    )
