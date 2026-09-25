import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import { useTranslation } from "react-i18next";
import { useStore } from "../StoreContext";
import { DeviceInfo } from "../Device";
import { WifiRenewal } from "./WifiRenewal";
import "./RenewalSetups.css";

type Evidence = { profile_expiry: number | null; last_success: number | null; last_attempt: number | null; outcome: string | { Failed: string } };
type Session = { stage: string; cause: string | null; httpStatus: number | null };
type Setup = {
  id: string; displayName: string; bundleId: string; phoneName: string; phoneId: string; account: string;
  teamId: string | null; archiveSha256: string; phoneOnly: boolean; paused: boolean; pendingInstall: boolean;
  needsConfirmation: boolean; canRecover: boolean; canRetryConnectivity: boolean; iphone: Evidence; nextAttempt: number | null; lastChecked: number | null;
  problem: string | null; accountProblem: string | null; accountSession: Session | null;
  attempt: { stage: string; session: Session | null } | null;
  failureEvidence: { failure: string; at: number } | null;
};
type Snapshot = { executionAvailable: boolean; setups: Setup[] };
type HostStatus = { available: boolean; running: boolean; exitPending: boolean; notice: string | null;
  settings: { pilotVersion: number; optedIn: boolean; paused: boolean; startAtLogin: boolean; anisetteUrl: string } };
type DesktopStatus = { preferences: { closeToTray: boolean }; notice: string | null };
type StartupStatus = { available: boolean; enabled: boolean; verified: boolean; canEnable: boolean; canDisable: boolean; notice: string | null };
type ActionResult = { id: string; reused: boolean; enabled: boolean };

export function RenewalSetups({ device, account, installOnce }: { device: DeviceInfo | null; account: string | null; installOnce: () => Promise<void> }) {
  const { t } = useTranslation();
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [host, setHost] = useState<HostStatus | null>(null);
  const [desktop, setDesktop] = useState<DesktopStatus | null>(null);
  const [startup, setStartup] = useState<StartupStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [controlBusy, setControlBusy] = useState(false);
  const [catalogBusy, setCatalogBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [detailsId, setDetailsId] = useState<string | null>(null);
  const [removeId, setRemoveId] = useState<string | null>(null);
  const [troubleshooting, setTroubleshooting] = useState(false);
  const [anisetteServer] = useStore<string>("anisetteServer", "ani.sidestore.io");
  const anisetteUrl = /^https?:\/\//i.test(anisetteServer) ? anisetteServer : `https://${anisetteServer}`;
  const request = useRef(0);
  const mounted = useRef(true);
  const date = (value: number | null) => value === null ? t("apps.unknown") : new Date(value * 1000).toLocaleString();
  const failure = (value: unknown) => typeof value === "string" ? value : t("apps.action_failed");
  const refresh = useCallback(async () => {
    const current = ++request.current;
    try {
      const [hostState, desktopState, startupState] = await Promise.all([
        invoke<HostStatus>("renewal_host_status"), invoke<DesktopStatus>("renewal_desktop_status"),
        invoke<StartupStatus>("renewal_startup_status").catch(() => ({ available: false, enabled: false, verified: false, canEnable: false, canDisable: false, notice: t("apps.startup_read_failed") })),
      ]);
      if (!mounted.current || current !== request.current) return;
      setHost(hostState); setDesktop(desktopState); setStartup(startupState);
      try {
        const state = await invoke<Snapshot>("renewal_setups");
        if (mounted.current && current === request.current) { setSnapshot(state); setCatalogBusy(false); }
      } catch (value) {
        if (typeof value === "string" && value.startsWith("Another installation")) {
          if (mounted.current && current === request.current) setCatalogBusy(true);
        } else { throw value; }
      }
    } catch (value) {
      if (mounted.current && current === request.current) setError(typeof value === "string" ? value : t("apps.action_failed"));
    }
  }, [t]);
  useEffect(() => {
    mounted.current = true; void refresh();
    const changed = listen("renewal-changed", () => { void refresh(); });
    return () => { mounted.current = false; request.current += 1; void changed.then(stop => stop()); };
  }, [refresh]);
  const act = async (action: () => Promise<unknown>, control = false) => {
    const setWorking = control ? setControlBusy : setBusy;
    setWorking(true); setError(null); setMessage(null);
    try { await action(); }
    catch (value) { if (mounted.current) setError(failure(value)); }
    finally { if (mounted.current) { await refresh(); setWorking(false); } }
  };
  const chooseIpa = async () => {
    const path = await open({ multiple: false, filters: [{ name: "IPA", extensions: ["ipa"] }] });
    return typeof path === "string" ? path : null;
  };
  const install = () => act(async () => {
    if (!device || device.connectionType !== "Network" || !account) throw t("apps.requirements");
    const appPath = await chooseIpa(); if (!appPath) return;
    const result = await invoke<ActionResult>("install_auto_renewal", { appPath, expectedPhone: device.udid, expectedAccount: account, anisetteUrl });
    setMessage(t(result.reused ? "apps.already_managed" : "apps.install_finished"));
  });
  const manage = (setup: Setup, action: string) => act(async () => {
    let appPath: string | null = null;
    if (action === "replace") { appPath = await chooseIpa(); if (!appPath) return; }
    await invoke("manage_renewal_app", { id: setup.id, action, appPath, anisetteUrl });
    setMessage(t("apps.action_finished"));
  });
  const configureHost = (paused: boolean) => act(() => invoke("configure_renewal_host", {
    settings: { ...host?.settings, pilotVersion: 1, optedIn: true, paused, startAtLogin: false, anisetteUrl },
  }), true);
  const safeWaiting = (setup: Setup) => setup.canRetryConnectivity && !setup.accountProblem
    && !setup.pendingInstall && !setup.needsConfirmation && ["Offline", "DeviceLocked"].includes(setup.problem ?? "");
  const status = (setup: Setup) => setup.accountProblem ? "attention" : setup.pendingInstall || setup.needsConfirmation ? "incomplete"
    : setup.problem && !safeWaiting(setup) ? "attention" : setup.paused ? "paused"
    : !host?.available || !host.settings.optedIn || host.settings.paused || host.exitPending ? "global_paused"
    : safeWaiting(setup) ? setup.nextAttempt !== null ? "waiting" : "attention" : "enabled";
  const closeMenu = (button: HTMLButtonElement) => button.closest("details")?.removeAttribute("open");
  const disabled = busy || host?.exitPending || !host?.available;

  return <div className="renewal-setups managed-apps">
    <div className="managed-header">
      <div><h2>{t("apps.title")}</h2><p className="settings-hint">{t("apps.subtitle")}</p></div>
      <div className="managed-install">
        <button className="managed-primary" disabled={disabled} onClick={() => void install()}>{t("apps.install_auto")}</button>
        <details className="managed-menu"><summary aria-label={t("apps.more_install")}>⋯</summary><div className="managed-menu-content">
          <button disabled={busy || host?.exitPending} onClick={event => { closeMenu(event.currentTarget); void act(installOnce); }}>{t("apps.install_once")}</button><span className="settings-hint">{t("apps.install_once_hint")}</span>
        </div></details>
      </div>
    </div>
    <p className="settings-hint managed-consent">{t("apps.consent")}</p>
    {(!device || device.connectionType !== "Network" || !account) && <p className="settings-hint">{t("apps.requirements")}</p>}
    {host?.available === false && <p className="renewal-notice">{t("apps.unavailable")}</p>}
    <div className="managed-host">
      <span role="status">{t(host?.exitPending ? "renewal.host_exiting" : host?.running ? "apps.running" : !host?.settings.optedIn || host.settings.paused ? "apps.host_paused" : "apps.host_on")}</span>
      <button disabled={controlBusy || !host?.available || host.exitPending} onClick={() => void configureHost(Boolean(host?.settings.optedIn && !host.settings.paused))}>
        {t(host?.settings.optedIn && !host.settings.paused ? "apps.pause_all" : "apps.resume_all")}
      </button>
    </div>
    <div aria-live="polite">
      {busy && <p role="status">{t("apps.working")}</p>}
      {error && <p className="managed-error" role="alert">{error}</p>}
      {message && <p role="status">{message}</p>}
      {catalogBusy && <p className="settings-hint">{t("apps.catalog_busy")}</p>}
    </div>
    {snapshot?.setups.length === 0 && <div className="managed-empty"><strong>{t("apps.empty")}</strong><p>{t("apps.empty_hint")}</p></div>}
    <ul className="managed-list" aria-label={t("apps.title")}>
      {snapshot?.setups.map(setup => <li key={setup.id}>
        <div className="managed-row">
          <div className="managed-app-name"><h3>{setup.displayName || setup.bundleId}</h3><span className="managed-app-phone">{setup.phoneName}</span></div>
          <div className="managed-app-state"><span className={`managed-status ${status(setup)}`}>{t(`apps.status.${status(setup)}`)}</span>
            <span className="managed-expiry">{t(setup.pendingInstall ? "apps.previous_expiry" : "apps.expiry", { date: date(setup.iphone.profile_expiry) })}</span>
            {status(setup) === "waiting" && <span className="managed-expiry">{t("apps.waiting_next", { date: date(setup.nextAttempt) })}</span>}</div>
          <details className="managed-menu"><summary aria-label={t("apps.app_actions", { app: setup.displayName })}>⋯</summary><div className="managed-menu-content">
            <button disabled={disabled || setup.needsConfirmation || setup.pendingInstall || !!setup.accountProblem || !setup.phoneOnly} onClick={event => { closeMenu(event.currentTarget); void manage(setup, "renew"); }}>{t("apps.renew")}</button>
            {setup.paused || setup.pendingInstall ? <button disabled={disabled || setup.needsConfirmation || !!setup.accountProblem} onClick={event => { closeMenu(event.currentTarget); void manage(setup, "resume"); }}>{t("apps.resume")}</button>
              : <button disabled={busy || host?.exitPending} onClick={event => { closeMenu(event.currentTarget); void act(async () => { await invoke("pause_renewal_setup", { id: setup.id }); setSnapshot(previous => previous ? { ...previous, setups: previous.setups.map(row => row.id === setup.id ? { ...row, paused: true, nextAttempt: null } : row) } : previous); setMessage(t("apps.pause_finished")); }); }}>{t("apps.pause")}</button>}
            <button disabled={disabled || setup.needsConfirmation || setup.pendingInstall || !!setup.accountProblem || !setup.phoneOnly} onClick={event => { closeMenu(event.currentTarget); void manage(setup, "replace"); }}>{t("apps.replace")}</button>
            <button onClick={event => { closeMenu(event.currentTarget); setDetailsId(detailsId === setup.id ? null : setup.id); }}>{t("apps.details")}</button>
            <button className="managed-remove" title={setup.accountProblem && setup.canRecover ? t("apps.recover_before_remove") : undefined} disabled={busy || host?.exitPending || (!!setup.accountProblem && setup.canRecover)} onClick={event => { closeMenu(event.currentTarget); setRemoveId(setup.id); }}>{t("apps.remove")}</button>
          </div></details>
        </div>
        {removeId === setup.id && <div className="managed-confirm" role="group" aria-label={t("apps.remove")}>
          <p>{t("apps.remove_explanation", { app: setup.displayName })}</p>
          <button disabled={busy} onClick={() => void act(async () => { await invoke("remove_renewal_setup", { id: setup.id }); setRemoveId(null); })}>{t("apps.confirm_remove")}</button>
          <button disabled={busy} onClick={() => setRemoveId(null)}>{t("common.cancel")}</button>
        </div>}
        {detailsId === setup.id && <section className="managed-details" aria-label={t("apps.details_for", { app: setup.displayName })}>
          <h4>{t("apps.details_for", { app: setup.displayName })}</h4>
          {setup.pendingInstall && <p className="managed-error">{t("apps.pending_explanation")}</p>}
          {(setup.accountProblem || setup.problem) && <p>{safeWaiting(setup) ? t(status(setup) === "waiting" ? "apps.waiting_explanation" : "apps.waiting_paused") : t(`renewal.problem.${setup.accountProblem || setup.problem}`)}</p>}
          {setup.accountProblem && setup.canRecover && <p>{t("apps.recover_before_remove")}</p>}
          {setup.canRecover && !safeWaiting(setup) && <><p>{t("apps.recover_explanation")}</p><button disabled={disabled} onClick={() => void manage(setup, "recover")}>{t("apps.recover")}</button></>}
          <dl>
            <dt>{t("apps.last_success")}</dt><dd>{date(setup.iphone.last_success)}</dd>
            <dt>{t("apps.next_check")}</dt><dd>{date(setup.nextAttempt)}</dd>
            <dt>{t("apps.account")}</dt><dd>{setup.account}</dd>
            <dt>{t("apps.bundle")}</dt><dd>{setup.bundleId}</dd>
            <dt>{t("apps.phone_id")}</dt><dd>{setup.phoneId}</dd>
            <dt>{t("apps.team")}</dt><dd>{setup.teamId ?? t("apps.unknown")}</dd>
            <dt>{t("apps.archive")}</dt><dd>{setup.archiveSha256}</dd>
          </dl>
          {setup.attempt && <p>{t("renewal.attempt_stage")}: {t(`renewal.attempt.${setup.attempt.stage}`)}</p>}
          {(setup.accountSession ?? setup.attempt?.session) && <p>{t("renewal.session_stage_label")}: {t(`renewal.session_stage.${(setup.accountSession ?? setup.attempt?.session)?.stage}`)}{(setup.accountSession ?? setup.attempt?.session)?.cause && ` · ${t(`renewal.session_cause.${(setup.accountSession ?? setup.attempt?.session)?.cause}`)}`}</p>}
          {setup.failureEvidence && <p>{t("renewal.previous_failure")}: {safeWaiting(setup) ? t("apps.waiting_history") : t(`renewal.problem.${setup.failureEvidence.failure}`)} · {date(setup.failureEvidence.at)}</p>}
          <p className="settings-hint">{t("apps.evidence_hint")}</p>
          <button onClick={() => setDetailsId(null)}>{t("apps.close_details")}</button>
        </section>}
      </li>)}
    </ul>
    <details className="managed-preferences"><summary>{t("apps.settings_details")}</summary>
      <label className="renewal-check"><input type="checkbox" checked={desktop?.preferences.closeToTray ?? false}
        disabled={controlBusy || !desktop || !host || host.exitPending || (!host.available && !desktop.preferences.closeToTray)}
        onChange={event => { const closeToTray = event.target.checked; void act(() => invoke("configure_renewal_desktop", { closeToTray }), true); }} />{t("renewal.close_to_tray")}</label>
      <p className="settings-hint">{t(desktop?.preferences.closeToTray ? "renewal.tray_enabled_hint" : "renewal.tray_disabled_hint")}</p>
      <label className="renewal-check"><input type="checkbox" checked={startup?.enabled ?? false}
        disabled={controlBusy || !startup?.available || !host?.available || host.exitPending || !(startup.enabled ? startup.canDisable : startup.canEnable)}
        onChange={event => { const enabled = event.target.checked; void act(() => invoke("configure_renewal_startup", { enabled }), true); }} />{t("apps.startup")}</label>
      <p className="settings-hint">{t("apps.startup_hint")}</p>
      {startup?.notice && <p role="status">{startup.notice}</p>}
      {host?.notice && <p>{host.notice}</p>}{desktop?.notice && <p>{desktop.notice}</p>}
      <button onClick={() => setTroubleshooting(!troubleshooting)}>{t("apps.troubleshooting")}</button>
      {troubleshooting && <WifiRenewal key={`${device?.udid}:${device?.connectionType}`} device={device} signedIn={!!account} />}
    </details>
  </div>;
}
