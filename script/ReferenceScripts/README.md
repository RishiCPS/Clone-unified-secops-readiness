Scripts in this folder are provided for reference only and should not be edited or modified.




# windows_events_checker_plus.ps1

## Purpose
- Automates a coverage assessment for Microsoft Sentinel analytic rules by comparing referenced Windows/Security Event IDs with IDs actually ingested into a target Log Analytics workspace.
- Optionally estimates billed volume for ingested Event IDs that are not referenced by any analytic rule, highlighting potential cost savings.

## End-to-End Flow
1. **Parameter Binding and Input Validation**
   - Accepts subscription and workspace identifiers and enforces mutually exclusive execution modes (ARM template analysis vs. live workspace inspection).
   - Provides optional switches for look-back period, WindowsEvent inclusion, UNION query mode, banner display, and unused-volume analysis.

2. **Utility Initialization**
   - Defines helper functions to display the script banner, verify Az PowerShell module availability, ensure an authenticated Az context, and run Kusto (KQL) queries through Log Analytics.
   - Leverages existing Azure PowerShell session tokens so no credentials are stored in the script.

3. **Startup Checks**
   - Prints the ASCII-art banner and ensures exactly one execution mode is selected with all required parameters supplied.
   - Confirms the required Az modules are present and that the current session is authenticated (`Connect-AzAccount`/`Select-AzSubscription`).

4. **Query Templates and Parsing Rules**
   - Prepares reusable KQL templates for SecurityEvent/WindowsEvent lookups and for billed-volume aggregation, with optional UNION of both tables.
   - Sets up a regular expression to extract numeric Event IDs from analytic rule KQL content.

5. **Analytic Rule Acquisition**
   - **ARM template mode:** Recursively loads JSON templates to collect embedded Sentinel analytic rule definitions, extracting display names and rule queries.
   - **autoCheck (live) mode:** Calls the Microsoft Sentinel Alert Rules REST API using `Invoke-AzRestMethod` against `/providers/Microsoft.SecurityInsights/alertRules` (multiple API versions attempted), and falls back to `Get-AzSentinelAlertRule` if required. Filters the results to scheduled rules that contain KQL.

6. **Rule Processing and Event ID Extraction**
   - Iterates through each analytic rule query, ensures it targets SecurityEvent/WindowsEvent tables, and extracts Event IDs using the prepared regex.
   - Builds per-rule summaries and a global set of all referenced Event IDs.

7. **Workspace Ingestion Discovery**
   - Runs Log Analytics KQL queries via `Invoke-AzOperationalInsightsQuery` to enumerate distinct Event IDs ingested during the requested time window.
   - Honors the WindowsEvent/UNION flags and gracefully falls back to SecurityEvent-only queries on failure.

8. **Coverage Analysis and Reporting**
   - Compares the Event IDs required by analytic rules with those observed in the workspace, printing per-rule present/missing lists.
   - Produces consolidated sets for missing IDs, covered IDs, and ingested-but-unused IDs.
   - Generates an XPath filter for configuring Windows Event Forwarding to collect the required Event IDs.

9. **Optional Billing Insight**
   - When unused Event IDs are detected, issues a billed-volume query that aggregates `_BilledSize` per Event ID, converts bytes to MB, and outputs a ranked table to identify expensive but unused logs.

## External APIs Invoked
- **Microsoft Sentinel Alert Rules REST API** (`/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/alertRules`)
  - Accessed via `Invoke-AzRestMethod` with multiple API versions, returning Sentinel analytic rule metadata for analysis.
- **Azure Log Analytics Query API**
  - Accessed through `Invoke-AzOperationalInsightsQuery` to execute KQL against the target workspace for Event ID discovery and billed-volume calculations.

## Authentication Model
- Relies on the authenticated Azure PowerShell context established by `Connect-AzAccount`/`Select-AzSubscription`.
- Helper function `Ensure-AzContext` validates the presence of that context; both REST and Log Analytics queries automatically inherit the cached OAuth tokens from the active session.
- No credentials or secrets are embedded or persisted by the script.

## Data Handling and Storage
- All analytic rule metadata, Event ID sets, and billing results are stored in in-memory PowerShell collections (lists, hash sets, ordered hash tables).
- Output is rendered to the console via formatted tables and text blocks.
- The script does not write any data to disk or external storage.
