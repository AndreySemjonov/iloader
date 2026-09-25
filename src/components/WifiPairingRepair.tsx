import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useTranslation } from "react-i18next";
import { DeviceInfo } from "../Device";
import { Modal } from "./Modal";

type RepairResult = {
  status: "completed" | "pending" | "locked" | "denied" | "deviceGone" |
    "wrongDevice" | "cancelled" | "failed" | "uncertain" | "partial";
  stage: string;
  pairAccepted: boolean;
  recordSaved: boolean;
  wifiServicesVerified: false;
};

export function WifiPairingRepair({ device, devices, disabled, onBusy, onUncertain }: {
  device: DeviceInfo | null;
  devices: DeviceInfo[];
  disabled: boolean;
  onBusy: (busy: boolean) => void;
  onUncertain: () => void;
}) {
  const { t } = useTranslation();
  const [target, setTarget] = useState<DeviceInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [attempts, setAttempts] = useState(0);
  const [result, setResult] = useState<RepairResult | null>(null);
  const [requestFailed, setRequestFailed] = useState(false);
  const [preflightError, setPreflightError] = useState<string | null>(null);
  const usbDevices = devices.filter(item => item.connectionType === "USB" && !item.networkAddress);

  const start = async () => {
    if (!target || busy || attempts >= 2) return;
    setBusy(true);
    onBusy(true);
    setStopping(false);
    setRequestFailed(false);
    setPreflightError(null);
    setAttempts(value => value + 1);
    try {
      const next = await invoke<RepairResult>("repair_wifi_pairing", { device: target });
      setResult(next);
      if (next.status === "partial" || next.status === "uncertain") onUncertain();
    } catch (error) {
      if (typeof error === "object" && error !== null && "type" in error && "message" in error && typeof error.message === "string") {
        // This command returns AppError only before starting the repair flow.
        setPreflightError(error.message);
        return;
      }
      // IPC loss is ambiguous too: do not assert the phone was unchanged.
      setRequestFailed(true);
      onUncertain();
    } finally {
      setBusy(false);
      onBusy(false);
    }
  };
  const retryAllowed = result?.status === "pending" || result?.status === "locked";

  return <>
    <button disabled={disabled || busy || usbDevices.length === 0}
      onClick={() => {
        setTarget(usbDevices.find(item => item.id === device?.id && item.udid === device.udid) ?? usbDevices[0]);
        setAttempts(0);
        setResult(null);
        setRequestFailed(false);
        setPreflightError(null);
        setStopping(false);
      }}>
      {t("wifiRepair.open")}
    </button>
    <Modal isOpen={target !== null} hideClose={busy}
      close={busy ? undefined : () => setTarget(null)}>
      <h2>{t("wifiRepair.title", { device: target?.name })}</h2>
      <label>{t("wifiRepair.target")}
        <select disabled={busy || attempts > 0} value={usbDevices.findIndex(item => item.id === target?.id && item.udid === target.udid)}
          onChange={event => setTarget(usbDevices[Number(event.target.value)] ?? null)}>
          {usbDevices.map((item, index) => <option key={`${item.udid}:${item.id}`} value={index}>{item.name} · USB</option>)}
        </select>
      </label>
      <p>{t("wifiRepair.explanation")}</p>
      <p>{t("wifiRepair.phonePrompt")}</p>
      {busy && <p role="status">{t(stopping ? "wifiRepair.stopping" : "wifiRepair.working")}</p>}
      {!busy && result && <div role="status">
        <p>{t(`wifiRepair.status.${result.status}`)}</p>
        {result.status === "partial" && <p>{t(result.recordSaved ? "wifiRepair.saved" : "wifiRepair.saveUnconfirmed")}</p>}
      </div>}
      {requestFailed && <p role="alert">{t("wifiRepair.requestFailed")}</p>}
      {preflightError && <p role="alert">{preflightError}</p>}
      {!busy && attempts >= 2 && retryAllowed && <p>{t("wifiRepair.retryLimit")}</p>}
      {!busy && !requestFailed && !preflightError && attempts < 2 && (!result || retryAllowed) &&
        <button onClick={start}>{t(attempts ? "wifiRepair.retry" : "wifiRepair.start")}</button>}
      {busy && <button disabled={stopping} onClick={async () => {
        setStopping(true);
        try { await invoke("cancel_wifi_pairing_repair"); }
        catch { /* Await the original result; cancellation is not a rollback. */ }
      }}>{t("wifiRepair.cancel")}</button>}
      {!busy && <button onClick={() => setTarget(null)}>{t("wifiRepair.close")}</button>}
    </Modal>
  </>;
}
