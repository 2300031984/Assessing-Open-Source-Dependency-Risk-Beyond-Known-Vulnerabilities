#!/usr/bin/env python3
"""
CYBER-100 CLI Demonstration Script
Assessing Open Source Dependency Risk Beyond Known Vulnerabilities

Demonstrates:
1. Application initialization & schema validation.
2. Offline DEMO FIXTURE risk assessment execution.
3. Factor-by-factor transparent risk breakdown.
4. Composite risk score calculation & tier classification.
5. Database persistence & retrieval verification.
6. Input validation & error handling.
"""

import sys
from pathlib import Path

# Ensure UTF-8 output encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.database.session import SessionLocal, init_db
from backend.app.services.analysis_service import AnalysisService

def run_demo():
    print("=" * 75)
    print("CYBER-100: ASSESSING OPEN SOURCE DEPENDENCY RISK BEYOND KNOWN VULNERABILITIES")
    print("KL University Capstone Project | Review-2 / PDR Demonstrator")
    print("=" * 75)


    # 1. Initialize Database
    print("\n[STEP 1] Initializing SQLite database schema...")
    init_db()
    db = SessionLocal()
    service = AnalysisService(db)
    print("[OK] Database initialized successfully.")

    # 2. Execute Demo Fixture Analysis
    demo_url = "https://github.com/demo-owner/sample-crypto-lib"
    print(f"\n[STEP 2] Executing Risk Assessment (DEMO FIXTURE Mode)...")
    print(f"Target Repository: {demo_url}")

    result = service.analyze_repository(demo_url, use_demo_fixture=True)

    print("\n[OK] Analysis completed successfully!")
    print(f"  * Analysis ID:        {result['analysis_id']}")
    print(f"  * Repository:         {result['repository']['owner']}/{result['repository']['name']}")
    print(f"  * Primary Language:   {result['repository']['language']}")
    print(f"  * License:            {result['repository']['license']}")
    print(f"  * Archived Status:    {'Yes' if result['repository']['archived'] else 'No (Active)'}")

    # 3. Factor Breakdown Table
    print("\n[STEP 3] Transparent Factor-by-Factor Risk Breakdown:")
    print("-" * 75)
    print(f"{'Risk Dimension':<22} | {'Raw Signal':<12} | {'Norm (0-1)':<10} | {'Weight':<8} | {'Contribution'}")
    print("-" * 75)

    risk_factors = result["risk_factors"]
    for name, factor in risk_factors.items():
        dim_title = name.replace("_", " ").title()
        raw = f"{factor.raw_value:.4f}"
        norm = f"{factor.normalized_value:.4f}"
        weight = f"{factor.weight:.2f}"
        contrib = f"{factor.weighted_contribution:.4f}"
        print(f"{dim_title:<22} | {raw:<12} | {norm:<10} | {weight:<8} | {contrib}")

    print("-" * 75)
    print(f"FINAL COMPOSITE SCORE:  {result['risk_score']:.4f} / 1.00")
    print(f"RISK CLASSIFICATION:    {result['risk_level']}")
    print("-" * 75)

    # 4. Natural Language Explanation
    print("\n[STEP 4] Explainable Risk Diagnosis:")
    print(f"\"{result['explanation']}\"")

    # 5. Database Persistence Verification
    print("\n[STEP 5] Verifying Audit Trail Persistence in SQLite...")
    retrieved = service.get_analysis_by_id(result["analysis_id"])
    if retrieved and retrieved["analysis_id"] == result["analysis_id"]:
        print(f"[OK] Analysis record successfully retrieved from database via ID: {retrieved['analysis_id']}")
        print(f"     Score matches: {retrieved['risk_score'] == result['risk_score']}")
    else:
        print("[FAIL] Persistence verification failed!")

    # 6. Negative Input Validation Demonstration
    print("\n[STEP 6] Demonstrating Defensive Input Validation...")
    invalid_url = "https://github.com/invalid/"
    try:
        service.analyze_repository(invalid_url, use_demo_fixture=False)
        print("[FAIL] Validation failed to catch malformed URL!")
    except ValueError as e:
        print(f"[OK] Malformed URL successfully rejected: {e}")

    db.close()
    print("\n" + "=" * 75)
    print("[SUCCESS] DEMONSTRATION COMPLETE: System is fully operational and review-ready.")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    run_demo()
