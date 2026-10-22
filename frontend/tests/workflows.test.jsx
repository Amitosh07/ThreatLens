import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import App from "../src/App";
import { api } from "../src/services/api";
import { alert, analysisId, brief, completed, packet, page, rule } from "./fixtures";

function mount(path) {
  render(<MemoryRouter initialEntries={[path]}><App /></MemoryRouter>);
}
function mockGet(handler) {
  return vi.spyOn(api, "get").mockImplementation(async (path, config = {}) => {
    if (path === "/health") return { data: { status: "ok", tshark: { available: true }, disclaimer: "Lab data only" } };
    return { data: await handler(path, config) };
  });
}

describe("capture to analysis", () => {
  it("rejects the wrong extension, submits a capture, polls processing, then navigates to stored results", async () => {
    const user = userEvent.setup();
    let polls = 0;
    const get = mockGet((path) => {
      if (path === `/analyses/${analysisId}`) {
        polls += 1;
        return polls === 1 ? { ...brief, status: "processing" } : completed;
      }
      if (path === `/analyses/${analysisId}/packets`) return page([packet]);
      throw new Error(`Unexpected GET ${path}`);
    });
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: brief });
    mount("/upload");
    fireEvent.change(screen.getByLabelText(/Drop a .pcap/), { target: { files: [new File(["bad"], "bad.txt")] } });
    expect(screen.getByRole("alert")).toHaveTextContent("Only .pcap and .pcapng");
    expect(screen.getByRole("button", { name: "Start analysis" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Drop a .pcap/), { target: { files: [new File(["pcap"], brief.original_filename)] } });
    await user.click(screen.getByRole("button", { name: "Start analysis" }));
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
    expect(post.mock.calls[0][0]).toBe("/uploads");
    expect(post.mock.calls[0][1].get("file").name).toBe(brief.original_filename);
    expect(await screen.findByText(/capture is processing/)).toBeVisible();
    expect(await screen.findByText(/4 packets were stored/, {}, { timeout: 3500 })).toBeVisible();
    await user.click(screen.getByRole("link", { name: "View results" }));
    expect(await screen.findByRole("heading", { name: brief.original_filename })).toBeVisible();
    expect(await screen.findByRole("table", { name: "Packet metadata" })).toHaveTextContent("192.0.2.10:51515");
    expect(get).toHaveBeenCalledWith(`/analyses/${analysisId}/packets`, expect.objectContaining({ params: expect.objectContaining({ page: 1 }) }));
  });

  it("shows an API upload rejection and a failed processing state without a results link", async () => {
    const user = userEvent.setup();
    mockGet((path) => {
      if (path === `/analyses/${analysisId}`) return { ...brief, status: "failed", error_message: "TShark could not parse capture." };
      throw new Error(`Unexpected GET ${path}`);
    });
    const post = vi.spyOn(api, "post").mockRejectedValueOnce({ response: { data: { detail: "Invalid capture format." } } }).mockResolvedValueOnce({ data: brief });
    mount("/upload");
    await user.upload(screen.getByLabelText(/Drop a .pcap/), new File(["x"], "capture.pcap"));
    await user.click(screen.getByRole("button", { name: "Start analysis" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid capture format.");
    await user.click(screen.getByRole("button", { name: "Start analysis" }));
    expect(await screen.findByText("TShark could not parse capture.")).toBeVisible();
    expect(screen.queryByRole("link", { name: "View results" })).not.toBeInTheDocument();
    expect(post).toHaveBeenCalledTimes(2);
  });
});

describe("evidence and configuration", () => {
  it("opens supporting packet evidence from an analysis alert, closes it, and follows its analysis link", async () => {
    const user = userEvent.setup();
    const get = mockGet((path, config) => {
      if (path === "/alerts") return page([alert]);
      if (path === "/analyses") return page([completed]);
      if (path === "/alerts/7") return { ...alert, packets: [packet] };
      if (path === `/analyses/${analysisId}`) return completed;
      if (path === `/analyses/${analysisId}/packets`) return page([packet]);
      throw new Error(`Unexpected GET ${path}`);
    });
    mount(`/alerts?analysis=${analysisId}`);
    expect(await screen.findByText("Sensitive Port Access")).toBeVisible();
    expect(get).toHaveBeenCalledWith("/alerts", expect.objectContaining({ params: expect.objectContaining({ analysis_id: analysisId }) }));
    await user.click(screen.getByRole("button", { name: "7" }));
    let dialog = await screen.findByRole("dialog", { name: "Alert evidence" });
    expect(within(dialog).getByText("Review the supporting packet.")).toBeVisible();
    expect(within(dialog).getByRole("table", { name: "Packet metadata" })).toHaveTextContent("198.51.100.7:22");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "7" }));
    dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("link", { name: "Open analysis" }));
    expect(await screen.findByRole("heading", { name: brief.original_filename })).toBeVisible();
  });

  it("validates a watchlist before PATCH and saves normalized rule edits", async () => {
    const user = userEvent.setup();
    mockGet((path) => {
      if (path === "/rules") return [rule];
      throw new Error(`Unexpected GET ${path}`);
    });
    const patch = vi.spyOn(api, "patch").mockImplementation(async (_path, body) => ({ data: { ...rule, ...body } }));
    mount("/rules");
    const card = (await screen.findByRole("heading", { name: rule.name })).closest("article");
    const scope = within(card);
    await user.clear(scope.getByRole("textbox", { name: /Sensitive destination ports/ }));
    await user.type(scope.getByRole("textbox", { name: /Sensitive destination ports/ }), "0, 70000");
    await user.click(scope.getByRole("button", { name: "Save rule" }));
    expect(scope.getByText(/ports between 1 and 65535/)).toBeVisible();
    expect(patch).not.toHaveBeenCalled();
    await user.clear(scope.getByRole("textbox", { name: /Sensitive destination ports/ }));
    await user.type(scope.getByRole("textbox", { name: /Sensitive destination ports/ }), "22, 443, 22");
    await user.selectOptions(scope.getByRole("combobox", { name: "Severity" }), "high");
    await user.click(scope.getByRole("checkbox", { name: "Enabled" }));
    await user.click(scope.getByRole("button", { name: "Save rule" }));
    await waitFor(() => expect(patch).toHaveBeenCalledWith("/rules/3", { enabled: false, severity: "high", parameters: { ports: [22, 443] } }));
    expect(await screen.findByText(/Later analyses use this configuration/)).toBeVisible();
  });
});

describe("reports", () => {
  it("downloads both formats using the API filename and reports a failed export", async () => {
    const user = userEvent.setup();
    let failNext = false;
    // Reports return a blob plus Content-Disposition; other responses use the shared contract fixture.
    const get = vi.spyOn(api, "get").mockImplementation(async (path, config = {}) => {
      if (path === "/health") return { data: { tshark: { available: true } } };
      if (path === "/analyses") return { data: page([completed]) };
      if (path === `/analyses/${analysisId}`) return { data: completed };
      if (path === `/analyses/${analysisId}/report`) {
        if (failNext) throw { response: { data: new Blob([JSON.stringify({ detail: "Export unavailable." })]) } };
        const format = config.params.format;
        return { data: new Blob([format === "json" ? "{}" : "id,rule\n"], { type: format === "json" ? "application/json" : "text/csv" }), headers: { "content-disposition": `attachment; filename="capture-report.${format}"` } };
      }
      throw new Error(`Unexpected GET ${path}`);
    });
    const create = vi.fn(() => "blob:test");
    const revoke = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: create });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revoke });
    const names = [];
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function () {
      names.push(this.download);
      expect(this.href).toBe("blob:test");
    });
    mount(`/reports?analysis=${analysisId}`);
    await screen.findByRole("button", { name: "Download JSON" });
    await user.click(screen.getByRole("button", { name: "Download JSON" }));
    expect(await screen.findByText("JSON report downloaded.")).toBeVisible();
    expect(click).toHaveBeenCalledOnce();
    expect(create).toHaveBeenCalledOnce();
    expect(revoke).toHaveBeenCalledWith("blob:test");
    expect(get).toHaveBeenCalledWith(`/analyses/${analysisId}/report`, { params: { format: "json" }, responseType: "blob" });
    await user.click(screen.getByRole("button", { name: "Download CSV" }));
    expect(await screen.findByText("CSV report downloaded.")).toBeVisible();
    expect(names).toEqual(["capture-report.json", "capture-report.csv"]);
    expect(get).toHaveBeenCalledWith(`/analyses/${analysisId}/report`, { params: { format: "csv" }, responseType: "blob" });
    failNext = true;
    await user.click(screen.getByRole("button", { name: "Download CSV" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Export unavailable.");
    expect(screen.queryByText("CSV report downloaded.")).not.toBeInTheDocument();
    expect(click).toHaveBeenCalledTimes(2);
  });
});
