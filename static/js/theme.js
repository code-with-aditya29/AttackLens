/* =========================================
   ATTACKLENS - UI INTERACTIONS
========================================= */


document.addEventListener("DOMContentLoaded", () => {

    console.log("AttackLens UI loaded successfully");


    /* =========================================
       1. THEME TOGGLE
    ========================================= */

    const themeToggle = document.getElementById("theme-toggle");


    function updateThemeIcon(theme) {

        if (!themeToggle) return;

        if (theme === "dark") {
            themeToggle.textContent = "☀";
        } else {
            themeToggle.textContent = "◐";
        }
    }


    function applyTheme(theme) {

        document.documentElement.setAttribute(
            "data-theme",
            theme
        );

        localStorage.setItem(
            "attacklens-theme",
            theme
        );

        updateThemeIcon(theme);
    }


    function getPreferredTheme() {

        const savedTheme = localStorage.getItem(
            "attacklens-theme"
        );


        if (savedTheme) {
            return savedTheme;
        }


        if (
            window.matchMedia(
                "(prefers-color-scheme: dark)"
            ).matches
        ) {
            return "dark";
        }


        return "light";
    }


    const currentTheme = getPreferredTheme();

    applyTheme(currentTheme);


    if (themeToggle) {

        themeToggle.addEventListener(
            "click",
            () => {

                const activeTheme =
                    document.documentElement.getAttribute(
                        "data-theme"
                    );


                const newTheme =
                    activeTheme === "dark"
                        ? "light"
                        : "dark";


                applyTheme(newTheme);

            }
        );

    }


    /* =========================================
       2. NAVIGATION INTERACTION
    ========================================= */

    const navItems =
        document.querySelectorAll(".nav-item");


    navItems.forEach((item) => {

        item.addEventListener(
            "click",
            () => {

                navItems.forEach((navItem) => {
                    navItem.classList.remove("active");
                });


                item.classList.add("active");

            }
        );

    });


    /* =========================================
       3. NEW SCAN BUTTON
    ========================================= */

    const newScanButton =
        document.querySelector(".primary-button");


    if (newScanButton) {

        newScanButton.addEventListener(
            "click",
            () => {

                alert(
                    "Scan functionality will be added in Phase 4."
                );

            }
        );

    }


    /* =========================================
       4. DASHBOARD CARD BUTTONS
    ========================================= */

    const secondaryButtons =
        document.querySelectorAll(
            ".secondary-button"
        );


    secondaryButtons.forEach((button) => {

        button.addEventListener(
            "click",
            () => {

                const action =
                    button.textContent.trim();


                alert(
                    action +
                    " functionality will be connected soon."
                );

            }
        );

    });


    /* =========================================
       5. SYSTEM STATUS ANIMATION
    ========================================= */

    const statusIndicator =
        document.querySelector(
            ".status-indicator"
        );


    if (statusIndicator) {

        setInterval(() => {

            statusIndicator.classList.toggle(
                "status-pulse"
            );

        }, 1000);

    }

});