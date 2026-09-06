(() => {
    "use strict";

    /* =====================================================
       ATTACKLENS
       Interactive Attack Path Visualization
       ===================================================== */

    const GRAPH_DATA_ID = "attack-path-graph-data";
    const GRAPH_CONTAINER_ID = "attack-path-graph";

    const RISK_COLORS = {
        LOW: "#22c55e",
        MEDIUM: "#f59e0b",
        HIGH: "#f97316",
        CRITICAL: "#ef4444",
        UNKNOWN: "#8b5cf6"
    };

    const ATTACKER_COLOR = "#8b5cf6";
    const DEFAULT_EDGE_COLOR = "#8b5cf6";

    let cy = null;
    let graphData = null;
    let initialLayoutOptions = null;


    /* =====================================================
       INITIALIZATION
       ===================================================== */

    document.addEventListener(
        "DOMContentLoaded",
        initializeAttackPathVisualization
    );


    function initializeAttackPathVisualization() {

        const dataElement =
            document.getElementById(
                GRAPH_DATA_ID
            );

        const graphContainer =
            document.getElementById(
                GRAPH_CONTAINER_ID
            );


        if (
            !dataElement ||
            !graphContainer
        ) {
            return;
        }


        if (
            typeof window.cytoscape !==
            "function"
        ) {

            showGraphError(
                "The graph library could not be loaded. " +
                "Refresh the page and try again."
            );

            return;
        }


        try {

            graphData =
                parseGraphData(
                    dataElement.textContent
                );

        } catch (error) {

            console.error(
                "AttackLens graph data error:",
                error
            );

            showGraphError(
                "Attack graph data could not be prepared."
            );

            return;
        }


        if (
            !Array.isArray(
                graphData.nodes
            ) ||
            graphData.nodes.length === 0
        ) {

            showGraphError(
                "No graph nodes are available."
            );

            return;
        }


        const elements =
            buildCytoscapeElements(
                graphData
            );


        initialLayoutOptions =
            getLayoutOptions(
                graphData
            );


        cy = window.cytoscape({

            container:
                graphContainer,

            elements:
                elements,

            style:
                getGraphStyles(),

            layout:
                initialLayoutOptions,

            minZoom:
                0.35,

            maxZoom:
                2.5,

            wheelSensitivity:
                0.18,

            boxSelectionEnabled:
                false,

            autoungrabify:
                false,

            userPanningEnabled:
                true,

            userZoomingEnabled:
                true

        });


        bindGraphEvents();

        bindGraphControls();

        populatePathSelector();


        cy.ready(() => {

            hideLoadingState();

            fitGraph();

        });

    }


    /* =====================================================
       GRAPH DATA
       ===================================================== */

    function parseGraphData(
        rawText
    ) {

        const parsed =
            JSON.parse(
                rawText || "{}"
            );


        return {

            nodes:
                Array.isArray(
                    parsed.nodes
                )
                    ? parsed.nodes
                    : [],

            edges:
                Array.isArray(
                    parsed.edges
                )
                    ? parsed.edges
                    : [],

            paths:
                Array.isArray(
                    parsed.paths
                )
                    ? parsed.paths
                    : [],

            statistics:
                parsed.statistics &&
                typeof parsed.statistics ===
                    "object"
                    ? parsed.statistics
                    : {}

        };

    }


    /* =====================================================
       CYTOSCAPE ELEMENT GENERATION
       ===================================================== */

    function buildCytoscapeElements(
        data
    ) {

        const nodes =
            data.nodes.map(
                (node) => ({

                    group:
                        "nodes",

                    data: {

                        id:
                            normalizeString(
                                node.id
                            ),

                        nodeType:
                            normalizeString(
                                node.node_type,
                                "asset"
                            ),

                        target:
                            normalizeNullableString(
                                node.target
                            ),

                        hostname:
                            normalizeString(
                                node.hostname,
                                "Unknown"
                            ),

                        riskScore:
                            normalizeNumber(
                                node.risk_score
                            ),

                        riskLevel:
                            normalizeRiskLevel(
                                node.risk_level
                            ),

                        criticality:
                            normalizeString(
                                node.criticality,
                                "--"
                            ),

                        exposure:
                            normalizeString(
                                node.exposure,
                                "--"
                            ),

                        operatingSystem:
                            normalizeString(
                                node.operating_system,
                                "--"
                            ),

                        openPorts:
                            normalizeArray(
                                node.open_ports
                            ),

                        services:
                            normalizeArray(
                                node.services
                            ),

                        vulnerabilityCount:
                            normalizeNonNegativeInteger(
                                node.vulnerability_count
                            ),

                        label:
                            buildNodeLabel(
                                node
                            )

                    }

                })
            );


        const validNodeIds =
            new Set(
                nodes.map(
                    (item) =>
                        item.data.id
                )
            );


        const edges =
            data.edges
                .map(
                    (
                        edge,
                        index
                    ) => {

                        const source =
                            normalizeString(
                                edge.source
                            );

                        const target =
                            normalizeString(
                                edge.target
                            );


                        if (
                            !validNodeIds.has(
                                source
                            ) ||
                            !validNodeIds.has(
                                target
                            )
                        ) {

                            return null;

                        }


                        return {

                            group:
                                "edges",

                            data: {

                                id:
                                    normalizeString(
                                        edge.id,
                                        `attack-edge-${index + 1}`
                                    ),

                                source:
                                    source,

                                target:
                                    target,

                                relationship:
                                    normalizeString(
                                        edge.relationship,
                                        "potential_relationship"
                                    ),

                                confidence:
                                    normalizeString(
                                        edge.confidence,
                                        "UNKNOWN"
                                    ).toUpperCase(),

                                score:
                                    normalizeNumber(
                                        edge.score
                                    ),

                                evidence:
                                    normalizeArray(
                                        edge.evidence
                                    ),

                                label:
                                    formatRelationshipLabel(
                                        edge.relationship
                                    )

                            }

                        };

                    }
                )
                .filter(
                    Boolean
                );


        return [
            ...nodes,
            ...edges
        ];

    }


    /* =====================================================
       NODE LABELS
       ===================================================== */

    function buildNodeLabel(
        node
    ) {

        if (
            normalizeString(
                node.node_type
            ).toLowerCase() ===
            "attacker"
        ) {

            return "External Attacker";

        }


        const target =
            normalizeNullableString(
                node.target
            );


        const hostname =
            normalizeString(
                node.hostname
            );


        if (
            hostname &&
            hostname.toLowerCase() !==
                "unknown"
        ) {

            return (
                `${hostname}\n` +
                `${target || ""}`
            ).trim();

        }


        return (
            target ||
            "Asset"
        );

    }


    /* =====================================================
       GRAPH LAYOUT
       ===================================================== */

    function getLayoutOptions(
        data
    ) {

        const nodeCount =
            data.nodes.length;


        if (
            nodeCount <= 1
        ) {

            return {

                name:
                    "grid",

                fit:
                    true,

                padding:
                    70,

                animate:
                    false

            };

        }


        return {

            name:
                "breadthfirst",

            directed:
                true,

            roots:
                findGraphRoots(
                    data
                ),

            spacingFactor:
                1.35,

            padding:
                55,

            fit:
                true,

            animate:
                false,

            avoidOverlap:
                true

        };

    }


    function findGraphRoots(
        data
    ) {

        const attacker =
            data.nodes.find(
                (node) =>

                    normalizeString(
                        node.node_type
                    ).toLowerCase() ===
                    "attacker"
            );


        if (
            attacker &&
            attacker.id
        ) {

            return (
                `#${escapeSelector(
                    attacker.id
                )}`
            );

        }


        const targets =
            new Set(

                data.edges.map(
                    (edge) =>
                        normalizeString(
                            edge.target
                        )
                )

            );


        const roots =
            data.nodes
                .map(
                    (node) =>
                        normalizeString(
                            node.id
                        )
                )
                .filter(
                    (id) =>
                        id &&
                        !targets.has(
                            id
                        )
                );


        if (
            roots.length === 0
        ) {

            return undefined;

        }


        return roots
            .map(
                (id) =>
                    `#${escapeSelector(
                        id
                    )}`
            )
            .join(",");

    }


    /* =====================================================
       CYTOSCAPE VISUAL STYLES
       ===================================================== */

    function getGraphStyles() {

        return [

            {

                selector:
                    "node",

                style: {

                    "background-color":
                        (element) =>
                            getNodeColor(
                                element.data()
                            ),

                    "border-width":
                        2,

                    "border-color":
                        "#ffffff",

                    "border-opacity":
                        0.85,

                    "label":
                        "data(label)",

                    "color":
                        getGraphTextColor(),

                    "font-size":
                        11,

                    "font-weight":
                        650,

                    "text-wrap":
                        "wrap",

                    "text-max-width":
                        120,

                    "text-valign":
                        "bottom",

                    "text-margin-y":
                        8,

                    "width":
                        54,

                    "height":
                        54,

                    "overlay-opacity":
                        0,

                    "transition-property":
                        "opacity, background-color, border-color, width, height",

                    "transition-duration":
                        "160ms"

                }

            },


            {

                selector:
                    'node[nodeType = "attacker"]',

                style: {

                    "shape":
                        "diamond",

                    "background-color":
                        ATTACKER_COLOR,

                    "width":
                        62,

                    "height":
                        62

                }

            },


            {

                selector:
                    "edge",

                style: {

                    "width":
                        2.3,

                    "line-color":
                        DEFAULT_EDGE_COLOR,

                    "target-arrow-color":
                        DEFAULT_EDGE_COLOR,

                    "target-arrow-shape":
                        "triangle",

                    "curve-style":
                        "bezier",

                    "arrow-scale":
                        1,

                    "label":
                        "data(label)",

                    "font-size":
                        9,

                    "color":
                        getMutedTextColor(),

                    "text-rotation":
                        "autorotate",

                    "text-background-color":
                        getGraphBackgroundColor(),

                    "text-background-opacity":
                        0.85,

                    "text-background-padding":
                        3,

                    "overlay-opacity":
                        0,

                    "transition-property":
                        "opacity, width, line-color, target-arrow-color",

                    "transition-duration":
                        "160ms"

                }

            },


            {

                selector:
                    ".is-selected",

                style: {

                    "border-width":
                        4,

                    "border-color":
                        "#a78bfa",

                    "width":
                        64,

                    "height":
                        64,

                    "z-index":
                        999

                }

            },


            {

                selector:
                    "edge.is-selected",

                style: {

                    "width":
                        4,

                    "line-color":
                        "#a78bfa",

                    "target-arrow-color":
                        "#a78bfa",

                    "z-index":
                        999

                }

            },


            {

                selector:
                    ".path-highlight",

                style: {

                    "opacity":
                        1,

                    "z-index":
                        1000

                }

            },


            {

                selector:
                    "node.path-highlight",

                style: {

                    "border-width":
                        4,

                    "border-color":
                        "#ffffff"

                }

            },


            {

                selector:
                    "edge.path-highlight",

                style: {

                    "width":
                        4.5,

                    "line-color":
                        "#f59e0b",

                    "target-arrow-color":
                        "#f59e0b"

                }

            },


            {

                selector:
                    ".path-muted",

                style: {

                    "opacity":
                        0.18

                }

            }

        ];

    }


    /* =====================================================
       GRAPH INTERACTIONS
       ===================================================== */

    function bindGraphEvents() {

        cy.on(
            "tap",
            "node",
            (event) => {

                clearDirectSelection();

                event.target.addClass(
                    "is-selected"
                );

                showNodeDetails(
                    event.target.data()
                );

                enableClearButton();

            }
        );


        cy.on(
            "tap",
            "edge",
            (event) => {

                clearDirectSelection();

                event.target.addClass(
                    "is-selected"
                );

                showEdgeDetails(
                    event.target.data()
                );

                enableClearButton();

            }
        );


        cy.on(
            "tap",
            (event) => {

                if (
                    event.target === cy
                ) {

                    clearAllSelections();

                }

            }
        );

    }


    /* =====================================================
       GRAPH CONTROLS
       ===================================================== */

    function bindGraphControls() {

        const fitButton =
            document.getElementById(
                "graph-fit-button"
            );

        const resetButton =
            document.getElementById(
                "graph-reset-button"
            );

        const clearButton =
            document.getElementById(
                "graph-clear-button"
            );

        const pathSelector =
            document.getElementById(
                "attack-path-selector"
            );


        fitButton?.addEventListener(
            "click",
            fitGraph
        );


        resetButton?.addEventListener(
            "click",
            () => {

                clearAllSelections();

                cy.layout(
                    initialLayoutOptions
                ).run();


                window.setTimeout(
                    () => {

                        fitGraph();

                    },
                    40
                );

            }
        );


        clearButton?.addEventListener(
            "click",
            clearAllSelections
        );


        pathSelector?.addEventListener(
            "change",
            (event) => {

                const index =
                    Number.parseInt(
                        event.target.value,
                        10
                    );


                if (
                    Number.isNaN(
                        index
                    )
                ) {

                    clearPathHighlight();

                    resetDetailsPanel();

                    disableClearButton();

                    return;

                }


                highlightAttackPath(
                    index
                );

            }
        );

    }


    /* =====================================================
       PATH SELECTOR
       ===================================================== */

    function populatePathSelector() {

        const selector =
            document.getElementById(
                "attack-path-selector"
            );


        if (
            !selector ||
            !Array.isArray(
                graphData.paths
            )
        ) {

            return;

        }


        graphData.paths.forEach(
            (
                path,
                index
            ) => {

                const option =
                    document.createElement(
                        "option"
                    );


                option.value =
                    String(
                        index
                    );


                const riskLevel =
                    normalizeRiskLevel(
                        path.risk_level
                    );


                const score =
                    normalizeNumber(
                        path.score
                    );


                const nodes =
                    normalizeArray(
                        path.nodes
                    );


                option.textContent =
                    `Path ${index + 1} — ${riskLevel}` +
                    (
                        score !== null
                            ? ` (${score}/100)`
                            : ""
                    ) +
                    (
                        nodes.length > 0
                            ? ` — ${nodes.length} nodes`
                            : ""
                    );


                selector.appendChild(
                    option
                );

            }
        );

    }


    /* =====================================================
       ATTACK PATH HIGHLIGHTING
       ===================================================== */

    function highlightAttackPath(
        index
    ) {

        clearDirectSelection();

        clearPathHighlight();


        const path =
            graphData.paths[
                index
            ];


        if (
            !path
        ) {

            return;

        }


        const nodeIds =
            new Set(

                normalizeArray(
                    path.nodes
                ).map(
                    (value) =>
                        normalizeString(
                            value
                        )
                )

            );


        const edgeIds =
            new Set(

                normalizeArray(
                    path.edges
                ).map(
                    (value) =>
                        normalizeString(
                            value
                        )
                )

            );


        cy.elements().addClass(
            "path-muted"
        );


        nodeIds.forEach(
            (nodeId) => {

                const node =
                    cy.getElementById(
                        nodeId
                    );


                if (
                    node &&
                    node.length > 0
                ) {

                    node
                        .removeClass(
                            "path-muted"
                        )
                        .addClass(
                            "path-highlight"
                        );

                }

            }
        );


        if (
            edgeIds.size > 0
        ) {

            edgeIds.forEach(
                (edgeId) => {

                    const edge =
                        cy.getElementById(
                            edgeId
                        );


                    if (
                        edge &&
                        edge.length > 0
                    ) {

                        edge
                            .removeClass(
                                "path-muted"
                            )
                            .addClass(
                                "path-highlight"
                            );

                    }

                }
            );

        } else {

            highlightEdgesBetweenPathNodes(
                Array.from(
                    nodeIds
                )
            );

        }


        showPathDetails(
            path,
            index
        );


        enableClearButton();


        const highlighted =
            cy.elements(
                ".path-highlight"
            );


        if (
            highlighted.length > 0
        ) {

            cy.animate({

                fit: {

                    eles:
                        highlighted,

                    padding:
                        70

                },

                duration:
                    250

            });

        }

    }


    function highlightEdgesBetweenPathNodes(
        nodeIds
    ) {

        for (
            let index = 0;
            index <
            nodeIds.length - 1;
            index += 1
        ) {

            const sourceId =
                nodeIds[
                    index
                ];

            const targetId =
                nodeIds[
                    index + 1
                ];


            cy.edges().forEach(
                (edge) => {

                    if (
                        edge.data(
                            "source"
                        ) === sourceId &&
                        edge.data(
                            "target"
                        ) === targetId
                    ) {

                        edge
                            .removeClass(
                                "path-muted"
                            )
                            .addClass(
                                "path-highlight"
                            );

                    }

                }
            );

        }

    }


    /* =====================================================
       NODE DETAILS
       ===================================================== */

    function showNodeDetails(
        data
    ) {

        const title =
            data.nodeType ===
            "attacker"
                ? "External Attacker"
                : (
                    data.hostname ||
                    data.target ||
                    "Asset"
                );


        setDetailsTitle(
            title
        );


        const rows = [

            [
                "Type",
                formatLabel(
                    data.nodeType
                )
            ],

            [
                "Target",
                data.target ||
                "External Entry"
            ],

            [
                "Hostname",
                data.hostname ||
                "Unknown"
            ],

            [
                "Risk",
                data.riskScore !== null
                    ? (
                        `${data.riskScore} / 100 ` +
                        `(${data.riskLevel})`
                    )
                    : "--"
            ],

            [
                "Criticality",
                data.criticality ||
                "--"
            ],

            [
                "Exposure",
                data.exposure ||
                "--"
            ],

            [
                "Operating System",
                data.operatingSystem ||
                "--"
            ],

            [
                "Open Ports",
                formatArrayValue(
                    data.openPorts
                )
            ],

            [
                "Security Findings",
                String(
                    data.vulnerabilityCount ??
                    0
                )
            ]

        ];


        renderDetailsRows(
            rows
        );

    }


    /* =====================================================
       EDGE DETAILS
       ===================================================== */

    function showEdgeDetails(
        data
    ) {

        setDetailsTitle(

            formatRelationshipLabel(
                data.relationship
            ) ||
            "Potential Relationship"

        );


        const rows = [

            [
                "Source",
                data.source ||
                "--"
            ],

            [
                "Target",
                data.target ||
                "--"
            ],

            [
                "Relationship",
                formatLabel(
                    data.relationship
                )
            ],

            [
                "Confidence",
                data.confidence ||
                "UNKNOWN"
            ],

            [
                "Score",
                data.score !== null
                    ? `${data.score} / 100`
                    : "--"
            ],

            [
                "Evidence",
                formatArrayValue(
                    data.evidence
                )
            ]

        ];


        renderDetailsRows(
            rows
        );

    }


    /* =====================================================
       PATH DETAILS
       ===================================================== */

    function showPathDetails(
        path,
        index
    ) {

        setDetailsTitle(
            `Attack Path ${index + 1}`
        );


        const score =
            normalizeNumber(
                path.score
            );


        const rows = [

            [
                "Risk",
                normalizeRiskLevel(
                    path.risk_level
                )
            ],

            [
                "Score",
                score !== null
                    ? `${score} / 100`
                    : "--"
            ],

            [
                "Confidence",
                normalizeString(
                    path.confidence,
                    "UNKNOWN"
                ).toUpperCase()
            ],

            [
                "Steps",
                String(
                    normalizeArray(
                        path.edges
                    ).length
                )
            ],

            [
                "Path",
                normalizeArray(
                    path.nodes
                ).join(
                    " → "
                ) ||
                "--"
            ]

        ];


        renderDetailsRows(
            rows
        );

    }


    /* =====================================================
       DETAILS PANEL
       ===================================================== */

    function renderDetailsRows(
        rows
    ) {

        const content =
            document.getElementById(
                "attack-path-details-content"
            );


        if (
            !content
        ) {

            return;

        }


        content.replaceChildren();


        rows.forEach(
            (
                [
                    label,
                    value
                ]
            ) => {

                const row =
                    document.createElement(
                        "div"
                    );

                row.className =
                    "attack-path-detail-row";


                const labelElement =
                    document.createElement(
                        "span"
                    );

                labelElement.className =
                    "attack-path-detail-key";

                labelElement.textContent =
                    label;


                const valueElement =
                    document.createElement(
                        "span"
                    );

                valueElement.className =
                    "attack-path-detail-value";

                valueElement.textContent =
                    value ||
                    "--";


                row.append(
                    labelElement,
                    valueElement
                );


                content.appendChild(
                    row
                );

            }
        );

    }


    function setDetailsTitle(
        title
    ) {

        const titleElement =
            document.getElementById(
                "attack-path-details-title"
            );


        if (
            titleElement
        ) {

            titleElement.textContent =
                title;

        }

    }


    function resetDetailsPanel() {

        setDetailsTitle(
            "Select a node or relationship"
        );


        const content =
            document.getElementById(
                "attack-path-details-content"
            );


        if (
            !content
        ) {

            return;

        }


        content.replaceChildren();


        const message =
            document.createElement(
                "p"
            );


        message.className =
            "attack-path-details-empty";


        message.textContent =
            "Click an asset, attacker node, or relationship " +
            "in the graph to inspect its security context.";


        content.appendChild(
            message
        );

    }


    /* =====================================================
       SELECTION MANAGEMENT
       ===================================================== */

    function clearAllSelections() {

        clearDirectSelection();

        clearPathHighlight();


        const selector =
            document.getElementById(
                "attack-path-selector"
            );


        if (
            selector
        ) {

            selector.value =
                "";

        }


        resetDetailsPanel();

        disableClearButton();

    }


    function clearDirectSelection() {

        if (
            !cy
        ) {

            return;

        }


        cy.elements().removeClass(
            "is-selected"
        );

    }


    function clearPathHighlight() {

        if (
            !cy
        ) {

            return;

        }


        cy.elements().removeClass(
            "path-highlight path-muted"
        );

    }


    /* =====================================================
       FIT GRAPH
       ===================================================== */

    function fitGraph() {

        if (
            !cy ||
            cy.elements().length === 0
        ) {

            return;

        }


        cy.animate({

            fit: {

                eles:
                    cy.elements(),

                padding:
                    55

            },

            duration:
                250

        });

    }


    /* =====================================================
       BUTTON STATES
       ===================================================== */

    function enableClearButton() {

        const button =
            document.getElementById(
                "graph-clear-button"
            );


        if (
            button
        ) {

            button.disabled =
                false;

        }

    }


    function disableClearButton() {

        const button =
            document.getElementById(
                "graph-clear-button"
            );


        if (
            button
        ) {

            button.disabled =
                true;

        }

    }


    /* =====================================================
       LOADING / ERROR STATES
       ===================================================== */

    function hideLoadingState() {

        const loadingElement =
            document.getElementById(
                "attack-graph-loading"
            );


        if (
            loadingElement
        ) {

            loadingElement.hidden =
                true;

        }

    }


    function showGraphError(
        message
    ) {

        const graphContainer =
            document.getElementById(
                GRAPH_CONTAINER_ID
            );


        const loadingElement =
            document.getElementById(
                "attack-graph-loading"
            );


        if (
            loadingElement
        ) {

            loadingElement.textContent =
                message;

            loadingElement.classList.add(
                "error"
            );

            loadingElement.hidden =
                false;

        }


        if (
            graphContainer
        ) {

            graphContainer.classList.add(
                "has-error"
            );

        }

    }


    /* =====================================================
       NODE COLOR
       ===================================================== */

    function getNodeColor(
        data
    ) {

        if (
            data.nodeType ===
            "attacker"
        ) {

            return ATTACKER_COLOR;

        }


        return (
            RISK_COLORS[
                data.riskLevel
            ] ||
            RISK_COLORS.UNKNOWN
        );

    }


    /* =====================================================
       NORMALIZATION HELPERS
       ===================================================== */

    function normalizeRiskLevel(
        value
    ) {

        const normalized =
            normalizeString(
                value,
                "UNKNOWN"
            ).toUpperCase();


        if (
            Object.prototype
                .hasOwnProperty.call(
                    RISK_COLORS,
                    normalized
                )
        ) {

            return normalized;

        }


        return "UNKNOWN";

    }


    function normalizeNumber(
        value
    ) {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {

            return null;

        }


        const numeric =
            Number(
                value
            );


        if (
            !Number.isFinite(
                numeric
            )
        ) {

            return null;

        }


        return Math.max(
            0,
            Math.min(
                100,
                Math.round(
                    numeric * 100
                ) / 100
            )
        );

    }


    function normalizeNonNegativeInteger(
        value
    ) {

        const numeric =
            Number.parseInt(
                value,
                10
            );


        if (
            !Number.isFinite(
                numeric
            ) ||
            numeric < 0
        ) {

            return 0;

        }


        return numeric;

    }


    function normalizeArray(
        value
    ) {

        return (
            Array.isArray(
                value
            )
                ? value
                : []
        );

    }


    function normalizeString(
        value,
        fallback = ""
    ) {

        if (
            value === null ||
            value === undefined
        ) {

            return fallback;

        }


        const text =
            String(
                value
            ).trim();


        return (
            text ||
            fallback
        );

    }


    function normalizeNullableString(
        value
    ) {

        const text =
            normalizeString(
                value
            );


        return (
            text ||
            null
        );

    }


    /* =====================================================
       DISPLAY FORMATTERS
       ===================================================== */

    function formatRelationshipLabel(
        value
    ) {

        return formatLabel(
            value ||
            "potential relationship"
        );

    }


    function formatLabel(
        value
    ) {

        return normalizeString(
            value,
            "--"
        )
            .replace(
                /[_-]+/g,
                " "
            )
            .replace(
                /\s+/g,
                " "
            )
            .replace(
                /\b\w/g,
                (
                    character
                ) =>
                    character.toUpperCase()
            );

    }


    function formatArrayValue(
        value
    ) {

        const values =
            normalizeArray(
                value
            );


        if (
            values.length === 0
        ) {

            return "--";

        }


        return values
            .map(
                (item) => {

                    if (
                        item &&
                        typeof item ===
                            "object"
                    ) {

                        if (
                            item.port !==
                            undefined
                        ) {

                            return String(
                                item.port
                            );

                        }


                        if (
                            item.name !==
                            undefined
                        ) {

                            return String(
                                item.name
                            );

                        }


                        return JSON.stringify(
                            item
                        );

                    }


                    return String(
                        item
                    );

                }
            )
            .join(
                ", "
            );

    }


    /* =====================================================
       THEME HELPERS
       ===================================================== */

    function getGraphTextColor() {

        return isDarkTheme()
            ? "#f5f3ff"
            : "#211b2e";

    }


    function getMutedTextColor() {

        return isDarkTheme()
            ? "#b8b1c8"
            : "#6f687d";

    }


    function getGraphBackgroundColor() {

        return isDarkTheme()
            ? "#181522"
            : "#ffffff";

    }


    function isDarkTheme() {

        return (
            document.documentElement
                .getAttribute(
                    "data-theme"
                ) ===
            "dark"
        );

    }


    /* =====================================================
       CYTOSCAPE SELECTOR ESCAPING
       ===================================================== */

    function escapeSelector(
        value
    ) {

        if (
            window.CSS &&
            typeof window.CSS.escape ===
                "function"
        ) {

            return window.CSS.escape(
                String(
                    value
                )
            );

        }


        return String(
            value
        ).replace(

            /([ !"#$%&'()*+,./:;<=>?@[\\\]^`{|}~])/g,

            "\\$1"

        );

    }

})();