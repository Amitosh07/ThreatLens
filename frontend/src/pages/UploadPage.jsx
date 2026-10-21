import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ErrorNote, StatusBadge } from "../components/ui";
import { usePolledAnalysis } from "../hooks/usePolledAnalysis";
import { api, errorMessage } from "../services/api";
import { formatBytes } from "../utils/format";

export default function UploadPage() {
  const [file, setFile] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [progress, setProgress] = useState(null);
  const [error, setError] = useState("");
  const [analysis, setAnalysis] = useState(null);
  const [uploading, setUploading] = useState(false);
  const { polled, pollError } = usePolledAnalysis(analysis?.id, analysis?.status);

  function chooseFile(next) {
    setError("");
    setAnalysis(null);
    setProgress(null);
    if (!next) {
      setFile(null);
      return;
    }
    const extension = next.name.split(".").pop()?.toLowerCase();
    if (!["pcap", "pcapng"].includes(extension)) {
      setFile(null);
      setError("Only .pcap and .pcapng files are accepted.");
      return;
    }
    setFile(next);
  }

  async function submit(event) {
    event.preventDefault();
    if (!file) {
      setError("Choose a capture file first.");
      return;
    }
    setUploading(true);
    setError("");
    setAnalysis(null);
    const body = new FormData();
    body.append("file", file);
    try {
      const response = await api.post("/uploads", body, {
        onUploadProgress: (eventProgress) => {
          if (!eventProgress.total) return;
          setProgress(Math.round((eventProgress.loaded / eventProgress.total) * 100));
        },
      });
      setProgress(100);
      setAnalysis(response.data);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setUploading(false);
    }
  }

  useEffect(() => {
    if (polled) setAnalysis(polled);
  }, [polled]);

  useEffect(() => {
    if (pollError) setError(pollError);
  }, [pollError]);

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <div>
        <h1 className="text-2xl font-semibold">Upload a capture</h1>
        <p className="mt-1 text-sm text-slate-400">
          The file is stored outside the web app and parsed with PyShark and TShark. A successful result is shown only after processing completes.
        </p>
      </div>
      <form className="card p-5" onSubmit={submit}>
        <label
          htmlFor="capture"
          onDragOver={(event) => {
            event.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragOver(false);
            chooseFile(event.dataTransfer.files?.[0]);
          }}
          className={`block cursor-pointer rounded-lg border border-dashed px-4 py-10 text-center ${
            dragOver ? "border-teal-300 bg-teal-300/10" : "border-line"
          }`}
        >
          <input
            id="capture"
            className="sr-only"
            type="file"
            accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
            onChange={(event) => chooseFile(event.target.files?.[0])}
          />
          <span className="text-sm text-slate-200">Drop a .pcap or .pcapng file, or click to browse.</span>
          {file ? (
            <span className="mt-2 block font-mono text-xs text-teal-100">
              {file.name} · {formatBytes(file.size)}
            </span>
          ) : (
            <span className="mt-2 block text-xs text-slate-500">Maximum upload size is 50 MB by default.</span>
          )}
        </label>
        {progress != null && uploading ? (
          <p className="mt-3 text-sm text-slate-300" role="status">
            Upload progress: {progress}%
          </p>
        ) : null}
        <div className="mt-4 flex justify-end">
          <button className="btn-primary" type="submit" disabled={!file || uploading}>
            {uploading ? "Uploading…" : "Start analysis"}
          </button>
        </div>
      </form>
      <ErrorNote message={error} />
      {analysis ? (
        <section className="card p-4" aria-live="polite">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge value={analysis.status} />
            <span className="text-sm">{analysis.original_filename}</span>
          </div>
          {analysis.status === "queued" || analysis.status === "processing" ? (
            <p className="mt-2 text-sm text-slate-400">The capture is {analysis.status}. Results are not ready yet.</p>
          ) : null}
          {analysis.status === "completed" ? (
            <p className="mt-3 text-sm text-emerald-100">
              Processing finished. {analysis.packet_count.toLocaleString()} packets were stored.
              <Link className="ml-2 text-teal-200 underline" to={`/analyses/${analysis.id}`}>
                View results
              </Link>
            </p>
          ) : null}
          {analysis.status === "failed" ? <p className="mt-2 text-sm text-rose-200">{analysis.error_message}</p> : null}
        </section>
      ) : null}
    </div>
  );
}
