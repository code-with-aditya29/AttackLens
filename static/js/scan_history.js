document.addEventListener(
    "DOMContentLoaded",
    function () {

        // ==========================================
        // ELEMENT REFERENCES
        // ==========================================

        const selectAll =
            document.getElementById(
                "select-all-scans"
            );

        const scanCheckboxes =
            document.querySelectorAll(
                ".scan-checkbox"
            );

        const bulkDeleteForm =
            document.getElementById(
                "bulk-delete-form"
            );

        const deleteSelectedButton =
            document.getElementById(
                "delete-selected-button"
            );

        const deleteButtons =
            document.querySelectorAll(
                ".delete-scan-button"
            );


        // ==========================================
        // STOP IF NO SCAN HISTORY CONTROLS EXIST
        // ==========================================

        if (
            !selectAll ||
            scanCheckboxes.length === 0
        ) {

            return;

        }


        // ==========================================
        // CREATE SELECTED COUNT
        // ==========================================

        const selectAllContainer =
            selectAll.closest(
                ".scan-history-select-all"
            );

        let selectedCountElement =
            document.getElementById(
                "selected-scan-count"
            );


        if (
            !selectedCountElement &&
            selectAllContainer
        ) {

            selectedCountElement =
                document.createElement(
                    "span"
                );

            selectedCountElement.id =
                "selected-scan-count";

            selectedCountElement.className =
                "selected-scan-count";

            selectAllContainer.appendChild(
                selectedCountElement
            );

        }


        // ==========================================
        // GET SELECTED COUNT
        // ==========================================

        function getSelectedCount() {

            return document.querySelectorAll(
                ".scan-checkbox:checked"
            ).length;

        }


        // ==========================================
        // UPDATE PAGE STATE
        // ==========================================

        function updateSelectionState() {

            const selectedCount =
                getSelectedCount();

            const totalScans =
                scanCheckboxes.length;


            // --------------------------------------
            // SELECT ALL STATE
            // --------------------------------------

            selectAll.checked =
                selectedCount === totalScans;

            selectAll.indeterminate =
                selectedCount > 0 &&
                selectedCount < totalScans;


            // --------------------------------------
            // SELECTED COUNT
            // --------------------------------------

            if (selectedCountElement) {

                selectedCountElement.textContent =
                    `${selectedCount} selected`;

            }


            // --------------------------------------
            // DELETE SELECTED BUTTON STATE
            // --------------------------------------

            if (deleteSelectedButton) {

                deleteSelectedButton.disabled =
                    selectedCount === 0;

            }

        }


        // ==========================================
        // SELECT / DESELECT ALL
        // ==========================================

        selectAll.addEventListener(
            "change",
            function () {

                scanCheckboxes.forEach(
                    function (checkbox) {

                        checkbox.checked =
                            selectAll.checked;

                    }
                );


                updateSelectionState();

            }
        );


        // ==========================================
        // INDIVIDUAL CHECKBOX CHANGE
        // ==========================================

        scanCheckboxes.forEach(
            function (checkbox) {

                checkbox.addEventListener(
                    "change",
                    function () {

                        updateSelectionState();

                    }
                );

            }
        );


        // ==========================================
        // BULK DELETE
        // ==========================================

        if (bulkDeleteForm) {

            bulkDeleteForm.addEventListener(
                "submit",
                function (event) {

                    const submitter =
                        event.submitter;


                    // ----------------------------------
                    // INDIVIDUAL DELETE BUTTON
                    // ----------------------------------

                    if (
                        submitter &&
                        submitter.id !==
                        "delete-selected-button"
                    ) {

                        return;

                    }


                    const selectedCount =
                        getSelectedCount();


                    // ----------------------------------
                    // NOTHING SELECTED
                    // ----------------------------------

                    if (selectedCount === 0) {

                        event.preventDefault();

                        window.alert(
                            "Please select at least one scan to delete."
                        );

                        return;

                    }


                    // ----------------------------------
                    // BULK DELETE CONFIRMATION
                    // ----------------------------------

                    const message =
                        selectedCount === 1
                            ? "Are you sure you want to delete the selected scan? This action cannot be undone."
                            : `Are you sure you want to delete ${selectedCount} selected scans? This action cannot be undone.`;


                    const confirmed =
                        window.confirm(
                            message
                        );


                    if (!confirmed) {

                        event.preventDefault();

                    }

                }
            );

        }


        // ==========================================
        // SINGLE DELETE CONFIRMATION
        // ==========================================

        deleteButtons.forEach(
            function (button) {

                // Skip bulk delete button

                if (
                    button.id ===
                    "delete-selected-button"
                ) {

                    return;

                }


                button.addEventListener(
                    "click",
                    function (event) {

                        const confirmed =
                            window.confirm(
                                "Are you sure you want to delete this scan? This action cannot be undone."
                            );


                        if (!confirmed) {

                            event.preventDefault();

                        }

                    }
                );

            }
        );


        // ==========================================
        // INITIAL STATE
        // ==========================================

        updateSelectionState();

    }
);