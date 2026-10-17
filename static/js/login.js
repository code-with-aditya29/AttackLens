
"use strict";

/*
 * AttackLens - Login Page
 *
 * Detects the browser's timezone and populates
 * the hidden timezone field before login.
 *
 * Uses no inline JavaScript or external libraries.
 */

document.addEventListener("DOMContentLoaded", function () {

    const timezoneInput = document.getElementById("timezone");

    if (!timezoneInput) {
        return;
    }

    try {

        const detectedTimezone = Intl.DateTimeFormat()
            .resolvedOptions()
            .timeZone;

        if (detectedTimezone) {
            timezoneInput.value = detectedTimezone;
        } else {
            timezoneInput.value = "";
        }

    } catch (error) {

        /*
         * If timezone detection fails, leave the
         * field empty.
         *
         * The Flask backend should safely fall
         * back to UTC.
         */

        timezoneInput.value = "";

    }

});
