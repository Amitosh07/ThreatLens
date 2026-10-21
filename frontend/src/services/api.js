import axios from "axios";

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE || "/api/v1",
});

export function errorMessage(error) {
  const detail = error?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map((item) => item.msg || "Invalid input.").join(" ");
  }
  if (!error?.response) {
    return "Cannot reach the ThreatLens API. Start the backend on 127.0.0.1:8000.";
  }
  return "The request failed.";
}

export async function downloadReport(analysisId, format) {
  try {
    const response = await api.get(`/analyses/${analysisId}/report`, {
      params: { format },
      responseType: "blob",
    });
    const disposition = response.headers["content-disposition"] || "";
    const match = disposition.match(/filename="([^"]+)"/);
    const filename = match?.[1] || `threatlens-report.${format}`;
    const url = URL.createObjectURL(response.data);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    if (error.response?.data instanceof Blob) {
      const text = await error.response.data.text();
      try {
        const payload = JSON.parse(text);
        throw new Error(typeof payload.detail === "string" ? payload.detail : "Report export failed.");
      } catch (parseError) {
        if (parseError instanceof SyntaxError) {
          throw new Error("Report export failed.");
        }
        throw parseError;
      }
    }
    throw new Error(errorMessage(error));
  }
}
