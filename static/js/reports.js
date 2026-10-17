
"use strict";

/*
 * AttackLens - Reports Page
 *
 * Browser timezone detection for:
 * 1. Completed scan selection
 * 2. PDF report generation
 *
 * External JavaScript for CSP compatibility.
 */

document.addEventListener("DOMContentLoaded", function () {

    let browserTimezone = "UTC";

    try {

        const detectedTimezone = Intl.DateTimeFormat()
            .resolvedOptions()
            .timeZone;

        if (
            typeof detectedTimezone === "string" &&
            detectedTimezone.trim() !== ""
        ) {
            browserTimezone = detectedTimezone;
        }

    } catch (error) {

        console.warn(
            "AttackLens could not detect the browser timezone.",
            error
        );

    }

    const selectionTimezone = document.getElementById(
        "report-selection-timezone"
    );

    const generationTimezone = document.getElementById(
        "report-generation-timezone"
    );

    if (selectionTimezone) {
        selectionTimezone.value = browserTimezone;
    }

    if (generationTimezone) {
        generationTimezone.value = browserTimezone;
    }

});
