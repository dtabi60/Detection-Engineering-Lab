import { useEffect, useState } from "react";

const API_BASE_URL = "http://127.0.0.1:8000";

const TABS = [
  "Overview",
  "Process Tree",
  "Storyline Logs",
  "Response Actions",
];

export default function AlertWorkspace({ activeAlertId, onClose }) {
  const [activeTab, setActiveTab] = useState("Overview");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [alertDetails, setAlertDetails] = useState(null);
  const [storyline, setStoryline] = useState(null);
  const [processTree, setProcessTree] = useState(null);
  const [responseActions, setResponseActions] = useState([]);

  useEffect(() => {
    if (!activeAlertId) return;

    let cancelled = false;

    async function loadAlertWorkspace() {
      setLoading(true);
      setError("");
      setActiveTab("Overview");

      try {
        const alertRes = await fetch(
          `${API_BASE_URL}/api/v1/alerts/${activeAlertId}`
        );

        if (!alertRes.ok) {
          throw new Error(`Failed to load alert ${activeAlertId}`);
        }

        const alertData = await alertRes.json();

        const alert =
          alertData?.investigation?.alert ||
          alertData?.alert ||
          alertData?.investigation ||
          alertData;

        const storylineId = alert?.storyline_id;
        const processGuid = alert?.process_guid || storylineId;

        const requests = [
          Promise.resolve(alertData),
          storylineId
            ? fetch(`${API_BASE_URL}/api/v1/storylines/${storylineId}`).then(
                (r) => (r.ok ? r.json() : null)
              )
            : Promise.resolve(null),
          processGuid
            ? fetch(`${API_BASE_URL}/api/v1/process-tree/${processGuid}`).then(
                (r) => (r.ok ? r.json() : null)
              )
            : Promise.resolve(null),
          fetch(
            `${API_BASE_URL}/api/v1/response-actions/${activeAlertId}`
          ).then((r) => (r.ok ? r.json() : null)),
        ];

        const [details, storylineData, processTreeData, actionsData] =
          await Promise.all(requests);

        if (cancelled) return;

        setAlertDetails(details);
        setStoryline(storylineData);
        setProcessTree(processTreeData);
        setResponseActions(actionsData?.actions || []);
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "Failed to load alert workspace");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadAlertWorkspace();

    return () => {
      cancelled = true;
    };
  }, [activeAlertId]);

  if (!activeAlertId) return null;

  const alert =
    alertDetails?.investigation?.alert ||
    alertDetails?.alert ||
    alertDetails?.investigation ||
    alertDetails ||
    {};

  async function runResponseAction(actionType) {
    const payload = {
      host_id: String(alert?.host_id || alert?.hostname || "unknown-host"),
      alert_id: String(activeAlertId),
      action_type: actionType,
      target_identifier: String(
        alert?.process_guid ||
          alert?.file_path ||
          alert?.host_id ||
          alert?.hostname ||
          "unknown-target"
      ),
    };

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/response-actions/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`Failed to run ${actionType}`);
      }

      const result = await response.json();

      setResponseActions((previous) => [result.action, ...previous]);
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/70 backdrop-blur-sm">
      <aside className="h-full w-full max-w-6xl overflow-hidden border-l border-slate-700 bg-slate-950 text-slate-100 shadow-2xl">
        <header className="flex items-start justify-between border-b border-slate-800 px-6 py-5">
          <div>
            <p className="text-xs uppercase tracking-widest text-cyan-400">
              Alert Workspace
            </p>
            <h2 className="mt-1 text-2xl font-semibold">
              {alert?.alert_name || alert?.title || "Investigation"}
            </h2>
            <div className="mt-2 flex flex-wrap gap-3 text-sm text-slate-400">
              <span>Alert ID: {activeAlertId}</span>
              <span>Host: {alert?.host_id || alert?.hostname || "Unknown"}</span>
              <span>Severity: {alert?.severity || "Unknown"}</span>
            </div>
          </div>

          <button
            onClick={onClose}
            className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:bg-slate-800"
          >
            Close
          </button>
        </header>

        <div className="flex h-[calc(100%-88px)]">
          <nav className="w-64 border-r border-slate-800 bg-slate-900/60 p-4">
            <div className="space-y-2">
              {TABS.map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`w-full rounded-lg px-4 py-3 text-left text-sm transition ${
                    activeTab === tab
                      ? "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/40"
                      : "text-slate-400 hover:bg-slate-800 hover:text-slate-100"
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>
          </nav>

          <main className="flex-1 overflow-y-auto p-6">
            {loading && (
              <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
                Loading investigation context...
              </div>
            )}

            {error && (
              <div className="mb-4 rounded-xl border border-red-500/40 bg-red-500/10 p-4 text-red-300">
                {error}
              </div>
            )}

            {!loading && activeTab === "Overview" && (
              <section className="space-y-4">
                <div className="grid grid-cols-4 gap-4">
                  <Metric label="Severity" value={alert?.severity || "Unknown"} />
                  <Metric label="Status" value={alert?.status || "Unknown"} />
                  <Metric label="Host" value={alert?.host_id || alert?.hostname || "Unknown"} />
                  <Metric label="MITRE" value={alert?.mitre_technique || "Unknown"} />
                </div>

                <Panel title="Alert Details">
                  <pre className="overflow-auto text-xs text-slate-300">
                    {JSON.stringify(alertDetails, null, 2)}
                  </pre>
                </Panel>
              </section>
            )}

            {!loading && activeTab === "Process Tree" && (
              <Panel title="Process Tree">
                <pre className="overflow-auto text-xs text-slate-300">
                  {JSON.stringify(processTree, null, 2)}
                </pre>
              </Panel>
            )}

            {!loading && activeTab === "Storyline Logs" && (
              <Panel title="Storyline Logs">
                <pre className="overflow-auto text-xs text-slate-300">
                  {JSON.stringify(storyline, null, 2)}
                </pre>
              </Panel>
            )}

            {!loading && activeTab === "Response Actions" && (
              <section className="space-y-5">
                <Panel title="Containment Actions">
                  <div className="flex flex-wrap gap-3">
                    {[
                      "Isolate Host",
                      "Kill Process",
                      "Quarantine File",
                      "Disconnect Network",
                      "Collect Forensic Package",
                    ].map((action) => (
                      <button
                        key={action}
                        onClick={() => runResponseAction(action)}
                        className="rounded-lg bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 hover:bg-cyan-400"
                      >
                        {action}
                      </button>
                    ))}
                  </div>
                </Panel>

                <Panel title="Response Action Audit History">
                  {responseActions.length === 0 ? (
                    <p className="text-sm text-slate-400">
                      No response actions recorded yet.
                    </p>
                  ) : (
                    <pre className="overflow-auto text-xs text-slate-300">
                      {JSON.stringify(responseActions, null, 2)}
                    </pre>
                  )}
                </Panel>
              </section>
            )}
          </main>
        </div>
      </aside>
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
      <p className="text-xs uppercase tracking-wider text-slate-500">{label}</p>
      <p className="mt-2 truncate text-lg font-semibold text-slate-100">
        {value}
      </p>
    </div>
  );
}

function Panel({ title, children }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
      <h3 className="mb-4 text-lg font-semibold text-slate-100">{title}</h3>
      {children}
    </div>
  );
}