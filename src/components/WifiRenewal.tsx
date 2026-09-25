import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { useTranslation } from "react-i18next";
import { DeviceInfo } from "../Device";

type ConnectionReport = {
  connected: boolean;
  transport: "appleDaemonNetwork" | "remotePairingRsd" | null;
  stage: string;
  problem: string | null;
  afcRead: boolean;
  installationProxyRead: boolean;
  watchVerified: false;
};

function ConnectionDetails({ report }: { report: ConnectionReport }) {
  const { t } = useTranslation();
  return <div>
    <p>{t(report.connected ? (report.transport === "remotePairingRsd" ? "wifi.watch_connected" : "wifi.connected") : "wifi.not_connected")}</p>
    {report.transport && <p>{t(`wifi.transport.${report.transport}`)}</p>}
    <p>{t("wifi.connection_stage", { stage: t(`wifi.stage.${report.stage}`) })}</p>
    {report.problem && <p>{t(`wifi.connection_problem.${report.problem}`)}</p>}
    <p>{t("wifi.services", { afc: t(report.afcRead ? "wifi.checked" : "wifi.not_checked"), proxy: t(report.installationProxyRead ? "wifi.checked" : "wifi.not_checked") })}</p>
    <p>{t("wifi.watch_not_checked")}</p>
    <button onClick={() => navigator.clipboard.writeText(JSON.stringify(report, null, 2)).catch(() => {})}>{t("wifi.copy_report")}</button>
  </div>;
}

type Report = {
  connection: ConnectionReport | null;
  wifiConnected: boolean;
  signing: string;
  signingDetail: { stage: string; component: string; cause: string; certificate: string | null; httpStatus: number | null; serviceCode: number | null } | null;
  installationDetail: { stage: string; cause: string; errorType: string; errorName: string | null; libraryCode: number | null; librarySubcode: number | null; platformCodes: string[]; domainCodes: string[]; descriptionContext: string[]; descriptionPresent: boolean; descriptionUnclassified: boolean; outcomeUncertain: boolean } | null;
  iphone: string;
  watch: string;
  iphoneProfileExpiry: number | null;
  watchProfileExpiry: number | null;
  completedAt: number | null;
  problem: string | null;
};

export function WifiRenewal({ device, signedIn }: { device: DeviceInfo | null; signedIn: boolean }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [connection, setConnection] = useState<ConnectionReport | null>(null);
  const [failed, setFailed] = useState(false);
  const request = useRef(0);
  useEffect(() => () => { request.current += 1; }, []);
  const direct = device?.connectionType === "Network";
  useEffect(() => {
    request.current += 1;
    setConnection(null); setReport(null); setFailed(false); setBusy(false);
  }, [device?.udid, device?.id, device?.connectionType]);
  const date = (value: number | null) => value === null ? t("wifi.unknown") : new Date(value * 1000).toLocaleString();

  return <div>
    <h2>{t("wifi.title")}</h2>
    <p className="settings-hint">{t("wifi.instructions")}</p>
    {!direct && <p>{t("wifi.select_direct")}</p>}
    <div className="action-row">
      <button disabled={busy || !direct} onClick={async () => {
        const current = ++request.current;
        setBusy(true); setFailed(false); setConnection(null); setReport(null);
        try {
          const connected = await invoke<ConnectionReport>("check_wifi_connection");
          if (request.current === current) setConnection(connected);
        }
        catch { if (request.current === current) setFailed(true); }
        finally { if (request.current === current) setBusy(false); }
      }}>{t("wifi.check")}</button>
      <button disabled={busy || !direct || !signedIn} onClick={async () => {
        const current = ++request.current;
        setBusy(true); setFailed(false); setConnection(null); setReport(null);
        try {
          const path = await open({ multiple: false, filters: [{ name: "IPA", extensions: ["ipa"] }] });
          if (!path || request.current !== current) return;
          const result = await invoke<Report>("renew_wifi", { appPath: path });
          if (request.current === current) setReport(result);
        } catch { if (request.current === current) setFailed(true); }
        finally { if (request.current === current) setBusy(false); }
      }}>{t("wifi.renew")}</button>
    </div>
    <div aria-live="polite">
      {busy && <p>{t("wifi.working")}</p>}
      {failed && <p>{t("wifi.request_failed")}</p>}
      {connection !== null && <ConnectionDetails report={connection} />}
      {report && <>
        <p>{t("wifi.attempt_time", { time: date(report.completedAt) })}</p>
        {report.connection && <ConnectionDetails report={report.connection} />}
        <p>{t("wifi.signing")}: {t(`wifi.status.${report.signing}`)}</p>
        {report.signingDetail && <div>
          <p>{t("wifi.signing_stage", { stage: t(`wifi.signingStage.${report.signingDetail.stage}`), component: t(`wifi.signingComponent.${report.signingDetail.component}`) })}</p>
          <p>{t(`wifi.signingCause.${report.signingDetail.cause}`)}</p>
          {report.signingDetail.certificate && report.signingDetail.certificate !== report.signingDetail.cause && <p>{t(`wifi.signingCause.${report.signingDetail.certificate}`)}</p>}
          {report.signingDetail.httpStatus !== null && <p>{t("wifi.http_status", { code: report.signingDetail.httpStatus })}</p>}
          {report.signingDetail.serviceCode !== null && <p>{t("wifi.service_code", { code: report.signingDetail.serviceCode })}</p>}
        </div>}
        <p>iPhone: {t(`wifi.status.${report.iphone}`)} · {t("wifi.profile_expiry")}: {date(report.iphoneProfileExpiry)}</p>
        {report.installationDetail && <div>
          <p>{t("wifi.installation_stage", { stage: t(`wifi.installStage.${report.installationDetail.stage}`) })}</p>
          <p>{t(`wifi.installCause.${report.installationDetail.cause}`)}</p>
          <p>{t("wifi.installation_error", { name: report.installationDetail.errorName ?? report.installationDetail.errorType })}</p>
          {report.installationDetail.libraryCode !== null && <p>{t("wifi.installation_library_code", { code: report.installationDetail.libraryCode, subcode: report.installationDetail.librarySubcode })}</p>}
          {report.installationDetail.platformCodes.map(code => <p key={code}>{t("wifi.installation_platform_code", { code })}</p>)}
          {report.installationDetail.domainCodes.map(code => <p key={code}>{code}</p>)}
          {report.installationDetail.descriptionContext.map(context => <p key={context}>{t(`wifi.installContext.${context}`)}</p>)}
          {report.installationDetail.descriptionUnclassified && <p>{t("wifi.installation_unclassified")}</p>}
          {report.installationDetail.outcomeUncertain && <p>{t("wifi.installation_uncertain")}</p>}
        </div>}
        <p>Apple Watch: {t(`wifi.status.${report.watch}`)} · {t("wifi.profile_expiry")}: {date(report.watchProfileExpiry)}</p>
        {report.problem && <p>{t(`wifi.problem.${report.problem}`)}</p>}
        <p className="settings-hint">{t("wifi.evidence")}</p>
        <button onClick={async () => {
          try { await navigator.clipboard.writeText(JSON.stringify(report, null, 2)); }
          catch { setFailed(true); }
        }}>{t("wifi.copy_report")}</button>
      </>}
    </div>
  </div>;
}
