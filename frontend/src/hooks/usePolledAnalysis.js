import { useEffect, useState } from "react";
import { api, errorMessage } from "../services/api";

export function usePolledAnalysis(analysisId, status) {
  const [polled, setPolled] = useState(null);
  const [pollError, setPollError] = useState("");

  useEffect(() => {
    if (!analysisId || status === "completed" || status === "failed") return undefined;
    let stop = false;
    async function refresh() {
      try {
        const response = await api.get(`/analyses/${analysisId}`);
        if (!stop) setPolled(response.data);
      } catch (error) {
        if (!stop) setPollError(errorMessage(error));
      }
    }
    refresh();
    const timer = setInterval(refresh, 1200);
    return () => {
      stop = true;
      clearInterval(timer);
    };
  }, [analysisId, status]);

  return { polled, pollError };
}
