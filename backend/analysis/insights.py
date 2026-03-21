"""
WeaknessIQ Analysis Engine
===========================
This is the core value of the application — insights NOT directly
available from the CWE website.

Analyses provided:
1. Top weakness categories by frequency and abstraction level
2. Exploit likelihood distribution across the catalogue
3. Language/platform risk profiles — which languages carry most CWEs
4. Relationship chain analysis — cascading vulnerability paths
5. Consequence severity mapping — what attackers can achieve
6. Detection gap analysis — weaknesses hardest to find

All queries use ORM — no raw SQL string formatting (CWE-89).
"""

import logging
from collections import Counter, defaultdict
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from backend.db.database import CWEModel

logger = logging.getLogger("weaknessiq.analysis")


# ── 1. Top Weakness Categories ────────────────────────────────────────────────
async def get_top_weaknesses(
    session: AsyncSession,
    abstraction: str | None = None,
    limit: int = 20
) -> list[dict]:
    """
    Returns most common weakness categories.
    Optionally filtered by abstraction level (Pillar/Class/Base/Variant).
    The CWE site shows individual entries — we show frequency patterns.
    """
    # Input validation — abstraction must be from known set (CWE-20)
    valid_abstractions = {"Pillar", "Class", "Base", "Variant", "Compound"}
    if abstraction and abstraction not in valid_abstractions:
        raise ValueError(f"Invalid abstraction. Must be one of: {valid_abstractions}")

    # Validated limit range
    limit = max(1, min(limit, 100))

    stmt = select(CWEModel)
    if abstraction:
        stmt = stmt.where(CWEModel.abstraction == abstraction)

    result = await session.execute(stmt)
    entries = result.scalars().all()

    # Aggregate consequence types across all CWEs
    consequence_counts: Counter = Counter()
    for entry in entries:
        for consequence in entry.common_consequences or []:
            consequence_counts[consequence] += 1

    # Build response — sorted by how many CWEs share this consequence
    top = [
        {"consequence": k, "cwe_count": v, "percentage": round(v / len(entries) * 100, 1)}
        for k, v in consequence_counts.most_common(limit)
    ] if entries else []

    return {
        "total_weaknesses_analysed": len(entries),
        "abstraction_filter": abstraction or "all",
        "top_consequences": top,
        "insight": "Consequences appearing in many CWEs represent systemic risk patterns "
                   "that a single fix category can address across many vulnerabilities."
    }


# ── 2. Exploit Likelihood Distribution ───────────────────────────────────────
async def get_exploit_likelihood_distribution(session: AsyncSession) -> dict:
    """
    Distribution of exploit likelihood across the entire CWE catalogue.
    Useful for prioritisation — focus on High likelihood weaknesses first.
    This cross-catalogue view is NOT available on the CWE website.
    """
    stmt = select(CWEModel.likelihood_of_exploit, func.count().label("count"))
    stmt = stmt.group_by(CWEModel.likelihood_of_exploit)

    result = await session.execute(stmt)
    rows = result.all()

    total = sum(r.count for r in rows)
    distribution = []

    likelihood_order = ["High", "Medium", "Low", None]
    rows_dict = {r.likelihood_of_exploit: r.count for r in rows}

    for level in likelihood_order:
        count = rows_dict.get(level, 0)
        distribution.append({
            "likelihood": level or "Unspecified",
            "count": count,
            "percentage": round(count / total * 100, 1) if total else 0
        })

    return {
        "total_weaknesses": total,
        "distribution": distribution,
        "insight": "High-likelihood weaknesses should be prioritised in secure code review. "
                   "Even 'Low' likelihood weaknesses in critical systems warrant attention."
    }


# ── 3. Language Risk Profiles ─────────────────────────────────────────────────
async def get_language_risk_profiles(session: AsyncSession) -> dict:
    """
    Which programming languages are associated with the most CWEs?
    Breaks down by exploit likelihood per language.
    Developers can use this to understand their language's risk surface.
    Unique insight — not shown on CWE site in aggregate form.
    """
    result = await session.execute(select(CWEModel))
    entries = result.scalars().all()

    language_data: dict = defaultdict(lambda: {
        "total": 0, "high": 0, "medium": 0, "low": 0, "unspecified": 0
    })

    for entry in entries:
        for platform in entry.applicable_platforms or []:
            if platform.get("type") == "Language" and platform.get("name"):
                lang = platform["name"]
                likelihood = (entry.likelihood_of_exploit or "Unspecified").lower()
                language_data[lang]["total"] += 1
                if likelihood in language_data[lang]:
                    language_data[lang][likelihood] += 1
                else:
                    language_data[lang]["unspecified"] += 1

    # Sort by total CWE count descending
    sorted_profiles = sorted(
        [{"language": lang, **data} for lang, data in language_data.items()],
        key=lambda x: x["total"],
        reverse=True
    )

    return {
        "language_profiles": sorted_profiles[:20],
        "insight": "Languages with high CWE counts often reflect manual memory management "
                   "or weak type systems. Use this to inform language choice for security-critical components."
    }


# ── 4. Relationship Chain Analysis ───────────────────────────────────────────
async def get_relationship_chains(
    session: AsyncSession,
    cwe_id: str,
    depth: int = 3
) -> dict:
    """
    Traces parent/child/peer relationships for a given CWE up to N levels deep.
    Reveals cascading vulnerability chains — if CWE-X exists, CWE-Y is also likely.
    This multi-level traversal is NOT available on the CWE site (which shows one level).

    depth is capped at 5 to prevent runaway queries (CWE-400).
    """
    # Input validation (CWE-20)
    if not cwe_id.isdigit():
        raise ValueError("CWE ID must be numeric")
    depth = max(1, min(depth, 5))  # Cap depth — DoS prevention

    visited = set()
    chain = []

    async def traverse(current_id: str, current_depth: int):
        if current_depth > depth or current_id in visited:
            return
        visited.add(current_id)

        result = await session.execute(
            select(CWEModel).where(CWEModel.cwe_id == current_id)
        )
        entry = result.scalar_one_or_none()
        if not entry:
            return

        node = {
            "cwe_id": entry.cwe_id,
            "name": entry.name,
            "abstraction": entry.abstraction,
            "likelihood": entry.likelihood_of_exploit,
            "depth": current_depth,
            "relationships": entry.related_weaknesses or []
        }
        chain.append(node)

        for rel in entry.related_weaknesses or []:
            if rel.get("nature") in ("ChildOf", "ParentOf", "PeerOf"):
                await traverse(rel.get("cwe_id", ""), current_depth + 1)

    await traverse(cwe_id, 0)

    return {
        "root_cwe": cwe_id,
        "depth_searched": depth,
        "nodes_found": len(chain),
        "chain": chain,
        "insight": f"CWE-{cwe_id} is connected to {len(chain)-1} related weaknesses within "
                   f"{depth} relationship levels. Fixing the root cause may mitigate all connected weaknesses."
    }


# ── 5. Detection Gap Analysis ─────────────────────────────────────────────────
async def get_detection_gaps(session: AsyncSession) -> dict:
    """
    Identifies weaknesses with few or no detection methods documented.
    These are the 'blind spots' in your security testing.
    Cross-catalogue detection analysis — unique to WeaknessIQ.
    """
    result = await session.execute(select(CWEModel))
    entries = result.scalars().all()

    no_detection = []
    single_detection = []
    well_detected = []

    for entry in entries:
        methods = entry.detection_methods or []
        count = len(methods)
        record = {
            "cwe_id": entry.cwe_id,
            "name": entry.name,
            "abstraction": entry.abstraction,
            "likelihood": entry.likelihood_of_exploit,
            "detection_method_count": count,
            "methods": methods
        }
        if count == 0:
            no_detection.append(record)
        elif count == 1:
            single_detection.append(record)
        else:
            well_detected.append(record)

    # Most dangerous gaps: high likelihood + no detection method
    critical_gaps = [
        e for e in no_detection
        if e["likelihood"] == "High"
    ]

    return {
        "total_analysed": len(entries),
        "no_detection_methods": len(no_detection),
        "single_detection_method": len(single_detection),
        "well_detected": len(well_detected),
        "critical_gaps": critical_gaps[:10],  # Top 10 most dangerous blind spots
        "insight": f"{len(critical_gaps)} weaknesses are High likelihood but have NO documented "
                   "detection methods — these represent your most dangerous blind spots."
    }


# ── 6. CWE Lookup (single entry) ─────────────────────────────────────────────
async def get_cwe_by_id(session: AsyncSession, cwe_id: str) -> dict | None:
    """Single CWE lookup by ID. Input validated before query."""
    if not cwe_id.isdigit():
        raise ValueError("CWE ID must be numeric")

    result = await session.execute(
        select(CWEModel).where(CWEModel.cwe_id == cwe_id)
    )
    entry = result.scalar_one_or_none()
    if not entry:
        return None

    return {
        "cwe_id": entry.cwe_id,
        "name": entry.name,
        "abstraction": entry.abstraction,
        "status": entry.status,
        "description": entry.description,
        "extended_description": entry.extended_description,
        "likelihood_of_exploit": entry.likelihood_of_exploit,
        "detection_methods": entry.detection_methods,
        "common_consequences": entry.common_consequences,
        "related_weaknesses": entry.related_weaknesses,
        "applicable_platforms": entry.applicable_platforms,
        "affected_resources": entry.affected_resources,
    }


# ── 7. Catalogue Summary ──────────────────────────────────────────────────────
async def get_catalogue_summary(session: AsyncSession) -> dict:
    """High-level stats about the loaded CWE catalogue."""
    total = await session.execute(select(func.count()).select_from(CWEModel))
    total_count = total.scalar()

    by_abstraction = await session.execute(
        select(CWEModel.abstraction, func.count().label("count"))
        .group_by(CWEModel.abstraction)
    )

    return {
        "total_weaknesses": total_count,
        "by_abstraction": [
            {"abstraction": r.abstraction, "count": r.count}
            for r in by_abstraction.all()
        ],
        "data_source": "MITRE CWE",
        "api_version": "1.0"
    }
