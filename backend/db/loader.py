"""
CWE Data Loader
================
Loads parsed CWE entries from the XML parser into the database.
Run once after downloading fresh CWE data.
"""

import logging
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from backend.db.database import CWEModel
from backend.parser.cwe_parser import CWEEntry

logger = logging.getLogger("weaknessiq.loader")


async def load_cwe_data(session: AsyncSession, entries: list[CWEEntry]) -> dict:
    """
    Bulk-load CWE entries into database.
    Uses upsert pattern — safe to re-run after data updates.
    All DB operations use ORM — no raw SQL (CWE-89 mitigation).
    """
    loaded = 0
    skipped = 0
    errors = 0

    logger.info(f"Loading {len(entries)} CWE entries into database...")

    for entry in entries:
        try:
            # Check if exists (parameterised — CWE-89)
            result = await session.execute(
                select(CWEModel).where(CWEModel.cwe_id == entry.cwe_id)
            )
            existing = result.scalar_one_or_none()

            model = CWEModel(
                cwe_id=entry.cwe_id,
                name=entry.name,
                abstraction=entry.abstraction,
                status=entry.status,
                description=entry.description,
                extended_description=entry.extended_description,
                likelihood_of_exploit=entry.likelihood_of_exploit,
                detection_methods=entry.detection_methods,
                common_consequences=entry.common_consequences,
                related_weaknesses=entry.related_weaknesses,
                applicable_platforms=entry.applicable_platforms,
                affected_resources=entry.affected_resources,
            )

            if existing:
                # Update existing record
                for col in ["name", "description", "abstraction", "status",
                            "likelihood_of_exploit", "detection_methods",
                            "common_consequences", "related_weaknesses",
                            "applicable_platforms", "affected_resources"]:
                    setattr(existing, col, getattr(model, col))
                skipped += 1
            else:
                session.add(model)
                loaded += 1

        except Exception as e:
            logger.error(f"Error loading CWE-{entry.cwe_id}: {e}")
            errors += 1

    await session.commit()

    result = {"loaded": loaded, "updated": skipped, "errors": errors}
    logger.info(f"Load complete: {result}")
    return result
