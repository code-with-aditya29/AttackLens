
"use strict";

/*
 * =========================================================
 * AttackLens - Scan Target Page
 * =========================================================
 *
 * Responsibilities:
 * - Synchronize scan profile dropdown and profile cards
 * - Update active profile styling
 * - Restore the correct visual state on form reset
 *
 * CSP-compatible:
 * - No inline JavaScript
 * - No inline event handlers
 * - No external libraries
 * =========================================================
 */

document.addEventListener("DOMContentLoaded", function () {

    const select = document.getElementById("scan_profile");

    const form = document.getElementById("scan-form");

    const profileCards = document.querySelectorAll(
        ".scan-profile-card"
    );

    if (!select || !form || profileCards.length === 0) {
        return;
    }

    // -----------------------------------------------------
    // Update the selected scan profile
    // -----------------------------------------------------

    function updateProfile(profile) {

        const validProfiles = [
            "quick",
            "standard",
            "detailed"
        ];

        if (!validProfiles.includes(profile)) {
            return;
        }

        select.value = profile;

        profileCards.forEach(function (card) {

            const radio = card.querySelector(
                'input[type="radio"]'
            );

            if (!radio) {
                return;
            }

            const isActive = radio.value === profile;

            card.classList.toggle(
                "active-profile",
                isActive
            );

            radio.checked = isActive;

        });

    }

    // -----------------------------------------------------
    // Profile card interactions
    // -----------------------------------------------------

    profileCards.forEach(function (card) {

        const radio = card.querySelector(
            'input[type="radio"]'
        );

        if (!radio) {
            return;
        }

        card.addEventListener("click", function () {

            updateProfile(radio.value);

        });

        radio.addEventListener("change", function () {

            if (radio.checked) {
                updateProfile(radio.value);
            }

        });

    });

    // -----------------------------------------------------
    // Dropdown interaction
    // -----------------------------------------------------

    select.addEventListener("change", function () {

        updateProfile(select.value);

    });

    // -----------------------------------------------------
    // Reset handling
    // -----------------------------------------------------

    form.addEventListener("reset", function () {

        /*
         * The browser restores form defaults after
         * the reset event.
         *
         * Queue the UI update so it runs afterward.
         */

        queueMicrotask(function () {

            updateProfile(select.value);

        });

    });

    // -----------------------------------------------------
    // Initial synchronization
    // -----------------------------------------------------

    updateProfile(select.value);

});
