document.addEventListener("DOMContentLoaded", function () {

    /* =========================================
       THEME MANAGEMENT
    ========================================= */

    const themeToggle =
        document.getElementById("theme-toggle");


    // Get saved theme

    const savedTheme =
        localStorage.getItem("attacklens-theme");


    // Detect system preference

    const systemDarkMode =
        window.matchMedia(
            "(prefers-color-scheme: dark)"
        ).matches;


    // Apply initial theme

    if (savedTheme) {

        document.documentElement.setAttribute(
            "data-theme",
            savedTheme
        );

    } else {

        const defaultTheme =
            systemDarkMode
                ? "dark"
                : "light";


        document.documentElement.setAttribute(
            "data-theme",
            defaultTheme
        );

    }


    /* =========================================
       UPDATE THEME BUTTON
    ========================================= */

    function updateThemeIcon() {

        if (!themeToggle) {
            return;
        }


        const currentTheme =
            document.documentElement.getAttribute(
                "data-theme"
            );


        if (currentTheme === "dark") {

            themeToggle.innerHTML = "☀";

            themeToggle.title =
                "Switch to Light Mode";

            themeToggle.setAttribute(
                "aria-label",
                "Switch to Light Mode"
            );

        } else {

            themeToggle.innerHTML = "☾";

            themeToggle.title =
                "Switch to Dark Mode";

            themeToggle.setAttribute(
                "aria-label",
                "Switch to Dark Mode"
            );

        }

    }


    /* =========================================
       THEME TOGGLE
    ========================================= */

    if (themeToggle) {

        updateThemeIcon();


        themeToggle.addEventListener(
            "click",
            function () {

                const currentTheme =
                    document.documentElement.getAttribute(
                        "data-theme"
                    );


                const newTheme =
                    currentTheme === "dark"
                        ? "light"
                        : "dark";


                // Apply new theme

                document.documentElement.setAttribute(
                    "data-theme",
                    newTheme
                );


                // Save user preference

                localStorage.setItem(
                    "attacklens-theme",
                    newTheme
                );


                // Update icon

                updateThemeIcon();

            }
        );

    }


    /* =========================================
       FLASH MESSAGE / TOAST SYSTEM
    ========================================= */

    const flashMessages =
        document.querySelectorAll(
            ".flash-message, .login-message"
        );


    flashMessages.forEach(function (message, index) {

        // Determine notification type

        let notificationType = "info";


        if (
            message.classList.contains("success")
        ) {

            notificationType = "success";

        } else if (
            message.classList.contains("error")
        ) {

            notificationType = "error";

        } else if (
            message.classList.contains("warning")
        ) {

            notificationType = "warning";

        }


        // Add toast classes

        message.classList.add(
            "toast-notification",
            notificationType
        );


        // Create close button

        const closeButton =
            document.createElement("button");


        closeButton.type = "button";

        closeButton.className =
            "toast-close-button";


        closeButton.innerHTML = "×";

        closeButton.setAttribute(
            "aria-label",
            "Close notification"
        );


        message.appendChild(
            closeButton
        );


        // Small delay for animation

        setTimeout(
            function () {

                message.classList.add(
                    "toast-show"
                );

            },
            100 + (index * 100)
        );


        // Close function

        function closeNotification() {

            message.classList.remove(
                "toast-show"
            );


            message.classList.add(
                "toast-hide"
            );


            setTimeout(
                function () {

                    message.remove();

                },
                300
            );

        }


        // Manual close

        closeButton.addEventListener(
            "click",
            closeNotification
        );


        // Automatically disappear

        const autoCloseTime =
            notificationType === "error"
                ? 6000
                : 4000;


        setTimeout(
            closeNotification,
            autoCloseTime
        );

    });


});