import { useEffect, useState } from "react";
import { ErrorNote, LoadingBlock } from "../components/ui";
import { api, errorMessage } from "../services/api";

function draftsFrom(rules) {
  return Object.fromEntries(
    rules.map((rule) => [
      rule.id,
      {
        enabled: rule.enabled,
        severity: rule.severity,
        parameters: structuredClone(rule.parameters),
        lists: Object.fromEntries(
          rule.parameter_schema
            .filter((field) => field.type !== "integer")
            .map((field) => [field.name, (rule.parameters[field.name] || []).join(", ")]),
        ),
      },
    ]),
  );
}

function validate(rule, draft) {
  const errors = {};
  const parameters = { ...draft.parameters };
  for (const field of rule.parameter_schema) {
    if (field.type === "integer") {
      const value = parameters[field.name];
      if (!Number.isInteger(value) || value < field.min || value > field.max) {
        errors[field.name] = `${field.label} must be an integer from ${field.min} to ${field.max}.`;
      }
    }
    if (field.type === "port_list") {
      const ports = String(draft.lists[field.name] || "")
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
      const parsed = ports.map((item) => Number(item));
      if (!parsed.length || parsed.length > (field.max_items || 100) || parsed.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) {
        errors[field.name] = "Enter 1 to 100 comma-separated ports between 1 and 65535.";
      } else {
        parameters[field.name] = [...new Set(parsed)];
      }
    }
    if (field.type === "protocol_list") {
      const names = String(draft.lists[field.name] || "")
        .split(",")
        .map((item) => item.trim().toUpperCase())
        .filter(Boolean);
      if (!names.length || names.length > (field.max_items || 60) || names.some((name) => !/^[A-Z0-9_-]{1,40}$/.test(name))) {
        errors[field.name] = "Enter comma-separated protocol names using letters, numbers, _ or -.";
      } else {
        parameters[field.name] = [...new Set(names)];
      }
    }
  }
  return { errors, parameters };
}

export default function RulesPage() {
  const [rules, setRules] = useState([]);
  const [drafts, setDrafts] = useState({});
  const [fieldErrors, setFieldErrors] = useState({});
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get("/rules")
      .then((response) => {
        setRules(response.data);
        setDrafts(draftsFrom(response.data));
      })
      .catch((err) => setError(errorMessage(err)))
      .finally(() => setLoading(false));
  }, []);

  function updateDraft(id, patch) {
    setDrafts((current) => ({ ...current, [id]: { ...current[id], ...patch } }));
  }

  async function save(rule) {
    const draft = drafts[rule.id];
    const { errors, parameters } = validate(rule, draft);
    setFieldErrors((current) => ({ ...current, [rule.id]: errors }));
    if (Object.keys(errors).length) return;
    setMessage("");
    setError("");
    try {
      const response = await api.patch(`/rules/${rule.id}`, {
        enabled: draft.enabled,
        severity: draft.severity,
        parameters,
      });
      setRules((current) => current.map((item) => (item.id === rule.id ? response.data : item)));
      setDrafts((current) => ({ ...current, [rule.id]: draftsFrom([response.data])[rule.id] }));
      setMessage(`${rule.name} saved. Later analyses use this configuration. Completed analyses keep their original snapshot.`);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  if (loading) return <LoadingBlock label="Loading rules" />;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold">Detection rules</h1>
        <p className="mt-1 max-w-3xl text-sm text-slate-400">
          Thresholds are stored in SQLite and copied onto each analysis when it runs. Changing a rule does not rewrite older results.
        </p>
      </div>
      <ErrorNote message={error} />
      {message ? <p className="rounded-md border border-emerald-900 bg-emerald-950/40 px-3 py-2 text-sm text-emerald-100">{message}</p> : null}
      <div className="space-y-4">
        {rules.map((rule) => {
          const draft = drafts[rule.id];
          if (!draft) return null;
          const errors = fieldErrors[rule.id] || {};
          return (
            <article key={rule.id} className="card p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h2 className="text-lg font-medium">{rule.name}</h2>
                  <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-400">{rule.description}</p>
                </div>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={draft.enabled}
                    onChange={(event) => updateDraft(rule.id, { enabled: event.target.checked })}
                  />
                  Enabled
                </label>
              </div>
              <div className="mt-4 grid gap-3 md:grid-cols-2">
                <label className="text-sm">
                  <span className="label">Severity</span>
                  <select className="field" value={draft.severity} onChange={(event) => updateDraft(rule.id, { severity: event.target.value })}>
                    {["info", "low", "medium", "high", "critical"].map((severity) => (
                      <option key={severity} value={severity}>
                        {severity}
                      </option>
                    ))}
                  </select>
                </label>
                {rule.parameter_schema.map((field) => (
                  <label key={field.name} className="text-sm">
                    <span className="label">{field.label}</span>
                    {field.type === "integer" ? (
                      <input
                        className="field"
                        type="number"
                        min={field.min}
                        max={field.max}
                        value={draft.parameters[field.name]}
                        onChange={(event) =>
                          updateDraft(rule.id, {
                            parameters: { ...draft.parameters, [field.name]: Number(event.target.value) },
                          })
                        }
                      />
                    ) : (
                      <textarea
                        className="field min-h-20"
                        value={draft.lists[field.name] || ""}
                        onChange={(event) => updateDraft(rule.id, { lists: { ...draft.lists, [field.name]: event.target.value } })}
                      />
                    )}
                    <span className="mt-1 block text-xs text-slate-500">{field.help}</span>
                    {errors[field.name] ? <span className="mt-1 block text-xs text-rose-300">{errors[field.name]}</span> : null}
                  </label>
                ))}
              </div>
              <div className="mt-4">
                <button type="button" className="btn-primary" onClick={() => save(rule)}>
                  Save rule
                </button>
              </div>
            </article>
          );
        })}
      </div>
    </div>
  );
}
