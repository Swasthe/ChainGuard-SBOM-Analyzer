import pandas as pd

from analyzer import (
    load_data,
    analyze_dependencies
)


def get_highest_severity(values):
    """Return the highest severity in a collection."""

    ranking = {
        "unknown": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }

    cleaned_values = [
        str(value).strip().lower()
        for value in values
        if str(value).strip()
    ]

    if not cleaned_values:
        return "unknown"

    return max(
        cleaned_values,
        key=lambda value:
            ranking.get(
                value,
                0
            )
    )


def get_strongest_evidence(values):
    """Return the strongest vulnerability evidence."""

    cleaned_values = {
        str(value).strip().lower()
        for value in values
    }

    if "confirmed" in cleaned_values:
        return "confirmed"

    if "potential" in cleaned_values:
        return "potential"

    return "none"


def find_shared_risks(results):
    """
    Find risky components used by two or more
    applications.
    """

    if results.empty:
        return pd.DataFrame()

    required_columns = [
        "dependency_id",
        "app_id",
        "app_name",
        "component",
        "version",
        "vulnerability_status",
        "license_status",
        "maintenance_status",
        "risk_score",
        "severity",
        "cve_count"
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in results.columns
    ]

    if missing_columns:

        raise ValueError(
            "Missing analysis columns: "
            + ", ".join(
                missing_columns
            )
        )

    working_results = results.copy()

    working_results[
        "risk_score"
    ] = pd.to_numeric(
        working_results[
            "risk_score"
        ],
        errors="coerce"
    ).fillna(0)

    working_results[
        "cve_count"
    ] = pd.to_numeric(
        working_results[
            "cve_count"
        ],
        errors="coerce"
    ).fillna(0)

    risky_results = working_results[
        (
            working_results[
                "vulnerability_status"
            ]
            != "none"
        )
        |
        (
            working_results[
                "license_status"
            ].isin(
                [
                    "conflict",
                    "unknown",
                    "conditional"
                ]
            )
        )
        |
        (
            working_results[
                "maintenance_status"
            ]
            == "unmaintained"
        )
        |
        (
            working_results[
                "risk_score"
            ]
            >= 50
        )
    ].copy()

    if risky_results.empty:
        return pd.DataFrame()

    risky_results = (
        risky_results.drop_duplicates(
            subset=[
                "dependency_id"
            ]
        )
    )

    shared_risks = (
        risky_results.groupby(
            "component"
        )
        .agg(
            affected_applications=(
                "app_id",
                "nunique"
            ),

            application_names=(
                "app_name",
                lambda values:
                    ", ".join(
                        sorted(
                            {
                                str(value)
                                for value in values
                                if str(value).strip()
                            }
                        )
                    )
            ),

            installed_versions=(
                "version",
                lambda values:
                    ", ".join(
                        sorted(
                            {
                                str(value)
                                for value in values
                                if str(value).strip()
                            }
                        )
                    )
            ),

            evidence_status=(
                "vulnerability_status",
                get_strongest_evidence
            ),

            maximum_risk_score=(
                "risk_score",
                "max"
            ),

            average_risk_score=(
                "risk_score",
                "mean"
            ),

            highest_severity=(
                "severity",
                get_highest_severity
            ),

            total_findings=(
                "dependency_id",
                "nunique"
            ),

            cve_count=(
                "cve_count",
                "sum"
            ),

            confirmed_findings=(
                "vulnerability_status",
                lambda values:
                    sum(
                        str(value).strip().lower()
                        == "confirmed"
                        for value in values
                    )
            ),

            potential_findings=(
                "vulnerability_status",
                lambda values:
                    sum(
                        str(value).strip().lower()
                        == "potential"
                        for value in values
                    )
            ),

            licence_conflicts=(
                "license_status",
                lambda values:
                    sum(
                        str(value).strip().lower()
                        == "conflict"
                        for value in values
                    )
            ),

            unmaintained_findings=(
                "maintenance_status",
                lambda values:
                    sum(
                        str(value).strip().lower()
                        == "unmaintained"
                        for value in values
                    )
            )
        )
        .reset_index()
    )

    shared_risks = shared_risks[
        shared_risks[
            "affected_applications"
        ]
        >= 2
    ].copy()

    if shared_risks.empty:
        return shared_risks

    shared_risks[
        "maximum_risk_score"
    ] = shared_risks[
        "maximum_risk_score"
    ].round(1)

    shared_risks[
        "average_risk_score"
    ] = shared_risks[
        "average_risk_score"
    ].round(1)

    shared_risks[
        "cve_count"
    ] = shared_risks[
        "cve_count"
    ].astype(int)

    return shared_risks.sort_values(
        by=[
            "maximum_risk_score",
            "affected_applications",
            "total_findings"
        ],
        ascending=[
            False,
            False,
            False
        ]
    ).reset_index(
        drop=True
    )


def simulate_component_fix(
    results,
    component_name
):
    """
    Estimate the result of removing the vulnerability
    contribution for one component.
    """

    if results.empty:
        return None

    component_results = results[
        results[
            "component"
        ]
        == component_name
    ].copy()

    if component_results.empty:
        return None

    component_results = (
        component_results.drop_duplicates(
            subset=[
                "dependency_id"
            ]
        )
    )

    affected_apps = sorted(
        component_results[
            "app_name"
        ]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    current_scores = pd.to_numeric(
        component_results[
            "risk_score"
        ],
        errors="coerce"
    ).fillna(0)

    if (
        "vulnerability_points"
        in component_results.columns
    ):

        vulnerability_points = pd.to_numeric(
            component_results[
                "vulnerability_points"
            ],
            errors="coerce"
        ).fillna(0)

    else:

        vulnerability_points = pd.Series(
            0,
            index=component_results.index,
            dtype=float
        )

    simulated_scores = (
        current_scores
        - vulnerability_points
    ).clip(
        lower=0
    )

    evidence_status = (
        get_strongest_evidence(
            component_results[
                "vulnerability_status"
            ]
        )
    )

    current_average = float(
        current_scores.mean()
    )

    simulated_average = float(
        simulated_scores.mean()
    )

    return {
        "component":
            component_name,

        "evidence_status":
            evidence_status,

        "affected_applications":
            len(affected_apps),

        "application_names":
            affected_apps,

        "dependency_findings":
            len(component_results),

        "current_average_score":
            round(
                current_average,
                1
            ),

        "simulated_average_score":
            round(
                simulated_average,
                1
            ),

        "estimated_score_reduction":
            round(
                current_average
                - simulated_average,
                1
            ),

        "critical_before":
            int(
                (
                    current_scores
                    >= 75
                ).sum()
            ),

        "critical_after":
            int(
                (
                    simulated_scores
                    >= 75
                ).sum()
            ),

        "high_or_critical_before":
            int(
                (
                    current_scores
                    >= 50
                ).sum()
            ),

        "high_or_critical_after":
            int(
                (
                    simulated_scores
                    >= 50
                ).sum()
            )
    }


if __name__ == "__main__":

    data = load_data()

    results = analyze_dependencies(
        data
    )

    shared_risks = find_shared_risks(
        results
    )

    print(
        "Official correlation completed."
    )

    print(
        "Shared risk components:",
        len(shared_risks)
    )

    if not shared_risks.empty:

        print(
            shared_risks.head(
                10
            ).to_string(
                index=False
            )
        )