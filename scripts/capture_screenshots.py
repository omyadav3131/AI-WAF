"""Capture reproducible screenshots of the running AI-WAF Streamlit console."""

from __future__ import annotations

import re
from pathlib import Path

from playwright.sync_api import Page, TimeoutError as PlaywrightTimeoutError, sync_playwright


ROOT = Path(__file__).resolve().parents[1]
IMAGES_DIR = ROOT / "docs" / "images"
BASE_URL = "http://localhost:8501"
VIEWPORT = {"width": 1440, "height": 900}
DEVICE_SCALE_FACTOR = 2

# Filename, expected class, preset label, attention token expected in the response.
CASES = [
    ("demo_benign.png", "BENIGN", "Benign: product listing", "product"),
    ("demo_sqli.png", "SQL Injection", "SQLi: tautology", "or"),
    ("demo_xss.png", "XSS", "XSS: script tag", "script"),
    ("demo_adversarial.png", "BENIGN", "Benign: search with SQL word", "select"),
]


def wait_for_streamlit(page: Page) -> None:
    page.goto(BASE_URL, wait_until="networkidle", timeout=120_000)
    page.get_by_role("tab", name="Analyze", exact=True).wait_for(state="visible", timeout=60_000)


def current_latency_text(page: Page) -> str:
    for item in page.locator(".status-item").all_inner_texts():
        if item.startswith("Last request:"):
            return item
    raise RuntimeError("The console did not show a Last request latency value.")


def select_preset(page: Page, preset: str) -> None:
    selectbox = page.locator('[data-testid="stSelectbox"] input[role="combobox"]').first
    selectbox.click()
    page.get_by_role("option", name=preset, exact=True).click()
    page.get_by_label("Raw HTTP request").wait_for(state="visible")
    page.wait_for_function(
        """(value) => {
            const textarea = document.querySelector('[data-testid="stTextArea"] textarea');
            return Boolean(textarea && textarea.value === value);
        }""",
        arg={
            "Benign: product listing": "GET /products?category=electronics&page=2 HTTP/1.1\nHost: shop.example.com\nUser-Agent: Mozilla/5.0\nAccept: text/html",
            "SQLi: tautology": "GET /search?q=' OR 1=1-- HTTP/1.1\nHost: shop.example.com\nUser-Agent: Mozilla/5.0",
            "XSS: script tag": "POST /comment HTTP/1.1\nHost: shop.example.com\nContent-Type: application/x-www-form-urlencoded\n\nbody=<script>alert(document.cookie)</script>",
            "Benign: search with SQL word": "GET /search?q=select+shoes HTTP/1.1\nHost: shop.example.com\nAccept: text/html",
        }[preset],
        timeout=30_000,
    )


def wait_for_fresh_result(page: Page, previous_latency: str) -> None:
    page.wait_for_function(
        """(previousLatency) => {
            const status = [...document.querySelectorAll('.status-item')]
                .find((item) => item.textContent.trim().startsWith('Last request:'));
            if (!status || status.textContent.trim() === previousLatency) return false;

            const view = document.querySelector('[data-testid="stAppViewBlockContainer"]')
                || document.querySelector('[data-testid="stAppViewContainer"]');
            const stale = document.querySelector('.stale, [data-stale="true"]');
            const opacity = view ? Number.parseFloat(getComputedStyle(view).opacity) : 1;
            return !stale && (!Number.isFinite(opacity) || opacity >= 0.99);
        }""",
        arg=previous_latency,
        timeout=120_000,
    )
    page.locator(".verdict .verdict-label").wait_for(state="visible", timeout=30_000)


def analyze_case(page: Page, preset: str, expected_token: str) -> tuple[str, str]:
    select_preset(page, preset)
    previous_latency = current_latency_text(page)
    page.get_by_role("button", name="Analyze", exact=True).click()
    wait_for_fresh_result(page, previous_latency)

    page.wait_for_timeout(1000)
    predicted = page.locator(".verdict .verdict-label").inner_text().strip()
    confidence_line = page.locator(".verdict .verdict-meta").first.inner_text().strip()
    match = re.search(r"Confidence:\s*([0-9]+(?:\.[0-9]+)?)%", confidence_line)
    if not match:
        raise RuntimeError(f"Could not read confidence from verdict: {confidence_line!r}")
    confidence = f"{float(match.group(1)) / 100:.4f}"

    tokens = [token.strip().lower() for token in page.locator(".attention-token").all_inner_texts()]
    if not any(expected_token.lower() in token for token in tokens):
        raise AssertionError(
            f"Preset {preset!r}: expected attention token {expected_token!r}; got {tokens!r}"
        )
    return predicted, confidence


def save_page(page: Page, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(path), full_page=True, animations="disabled")


def capture_batch(page: Page) -> None:
    batch_tab = page.get_by_role("tab", name="Batch Test", exact=True)
    if not batch_tab.count():
        return
    batch_tab.click()
    run_button = page.get_by_role("button", name="Run all tests", exact=True)
    run_button.wait_for(state="visible", timeout=30_000)
    run_button.click()

    page.wait_for_function(
        "document.querySelectorAll('.result-table tbody tr').length === 15",
        timeout=900_000,
    )
    rows = page.locator(".result-table tbody tr")
    if rows.count() != 15:
        raise AssertionError(f"Expected 15 batch rows, found {rows.count()}.")

    row_nine = rows.nth(8).inner_text()
    if "DROP TABLE" not in row_nine or "BENIGN" not in row_nine or "51.30%" not in row_nine or "FAIL" not in row_nine:
        print(f"Batch row 9 differs from the requested reference: {row_nine}")

    rows.nth(14).scroll_into_view_if_needed()
    page.wait_for_timeout(1000)
    save_page(page, IMAGES_DIR / "demo_batch_test.png")


def capture_model_info(page: Page) -> None:
    info_tab = page.get_by_role("tab", name="Model Info", exact=True)
    if not info_tab.count():
        return
    info_tab.click()
    page.get_by_text("Model information", exact=True).wait_for(state="visible", timeout=30_000)
    page.wait_for_timeout(1000)
    save_page(page, IMAGES_DIR / "demo_model_info.png")


def main() -> None:
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    summary: list[tuple[str, str, str, str, str]] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(viewport=VIEWPORT, device_scale_factor=DEVICE_SCALE_FACTOR)
        page = context.new_page()
        wait_for_streamlit(page)

        for filename, expected, preset, expected_token in CASES:
            try:
                predicted, confidence = analyze_case(page, preset, expected_token)
            except AssertionError as error:
                print(f"ASSERTION FAILED: {error}. Screenshot not saved.")
                summary.append((filename, expected, "ASSERTION FAILED", "n/a", "NOT SAVED"))
                continue

            passed = predicted == expected
            destination = IMAGES_DIR / filename
            if not passed:
                destination = IMAGES_DIR / "_review" / filename
            save_page(page, destination)
            summary.append(
                (
                    str(destination.relative_to(ROOT)),
                    expected,
                    predicted,
                    confidence,
                    "PASS" if passed else "FAIL",
                )
            )

        capture_batch(page)
        capture_model_info(page)
        context.close()
        browser.close()

    print("file | expected | predicted | confidence | result")
    print("--- | --- | --- | ---: | ---")
    for row in summary:
        print(" | ".join(row))


if __name__ == "__main__":
    try:
        main()
    except PlaywrightTimeoutError as error:
        raise SystemExit(f"Screenshot capture timed out: {error}") from error
