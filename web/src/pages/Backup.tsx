import React, { useState } from 'react';
import { Archive, Play, Download, CheckCircle2, XCircle, Loader2, Link2 } from 'lucide-react';
import { secureFetch } from '../api';

export const Backup: React.FC = () => {
  const [runningDrill, setRunningDrill] = useState<boolean>(false);
  const [drillResult, setDrillResult] = useState<any>(null);
  const [remoteUrl, setRemoteUrl] = useState<string>('');
  const [pairCode, setPairCode] = useState<string>('');
  const [pairStatus, setPairStatus] = useState<string>('');
  const [pairingLoading, setPairingLoading] = useState<boolean>(false);

  const runDrill = async () => {
    setRunningDrill(true);
    setDrillResult(null);
    try {
      const resp = await secureFetch('/api/backup/drill', { method: 'POST' });
      const data = await resp.json();
      setDrillResult(data);
    } catch (err) {
      setDrillResult({
        passed: false,
        error_message: 'Drill execution failed to connect',
        checks: [],
      });
    } finally {
      setRunningDrill(false);
    }
  };

  const handlePairRemote = async (e: React.FormEvent) => {
    e.preventDefault();
    setPairingLoading(true);
    setPairStatus('');
    try {
      const resp = await secureFetch('/api/backup/pair-remote', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recovery_url: remoteUrl,
          pairing_code: pairCode,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Pairing failed');
      setPairStatus('Successfully paired with KyRecovery instance!');
      setPairCode('');
    } catch (err) {
      setPairStatus(err instanceof Error ? err.message : 'Pairing failed');
    } finally {
      setPairingLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '1080px', margin: '0 auto', padding: '32px 20px' }}>
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Archive size={24} style={{ color: 'var(--accent)' }} />
          <span>KyBackup & Recovery (Feature 0)</span>
        </h1>
        <p style={{ color: 'var(--ink)', fontSize: '14px', marginTop: '4px' }}>
          Continuous disaster recovery verification, Shamir split custodian key management, and automated sandbox restore drills.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))', gap: '20px', marginBottom: '24px' }}>
        {/* On-Demand Restore Drill Card */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3 style={{ fontSize: '16px' }}>Self-Test Restore Drill</h3>
              <p style={{ color: 'var(--ink)', fontSize: '13px' }}>
                Extracts encapsulated capsule into an isolated 0700 sandbox and tests DB integrity.
              </p>
            </div>
            <button type="button" onClick={runDrill} disabled={runningDrill}>
              {runningDrill ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
              <span>{runningDrill ? 'Running Drill...' : 'Run Live Drill'}</span>
            </button>
          </div>

          {drillResult && (
            <div
              style={{
                marginTop: '16px',
                background: 'var(--bg)',
                border: '1px solid var(--line)',
                borderRadius: '6px',
                padding: '16px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span style={{ fontWeight: 600, fontSize: '14px' }}>Drill Outcome:</span>
                <span className={`badge badge-${drillResult.passed ? 'success' : 'danger'}`}>
                  {drillResult.passed ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
                  <span>{drillResult.passed ? 'ALL CHECKS PASSED' : 'DRILL FAILED'}</span>
                </span>
              </div>

              {drillResult.duration_ms !== undefined && (
                <div style={{ fontSize: '12px', color: 'var(--ink)', marginBottom: '8px' }}>
                  Execution duration: <code style={{ color: 'var(--accent)' }}>{drillResult.duration_ms}ms</code>
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {drillResult.checks?.map((check: any, idx: number) => (
                  <div
                    key={idx}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      fontSize: '13px',
                      padding: '4px 0',
                      borderBottom: '1px solid var(--line)',
                    }}
                  >
                    {check.passed ? (
                      <CheckCircle2 size={14} style={{ color: 'var(--success)', flexShrink: 0 }} />
                    ) : (
                      <XCircle size={14} style={{ color: 'var(--danger)', flexShrink: 0 }} />
                    )}
                    <span style={{ fontWeight: 500 }}>{check.name}:</span>
                    <span style={{ color: 'var(--ink)' }}>{check.message}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Sealed Recovery Capsule & KyRecovery Pairing */}
        <div className="panel">
          <h3 style={{ fontSize: '16px', marginBottom: '4px' }}>Sealed Recovery Capsule</h3>
          <p style={{ color: 'var(--ink)', fontSize: '13px', marginBottom: '16px' }}>
            Download the backup sealed to your KyRecovery public key. Only the custodian shares open it.
          </p>

          <a
            href="/api/backup/export-capsule"
            download
            className="btn btn-secondary"
            style={{ textDecoration: 'none', display: 'inline-flex', marginBottom: '24px' }}
          >
            <Download size={16} />
            <span>Download sealed capsule (.kycap)</span>
          </a>

          <div style={{ borderTop: '1px solid var(--line)', paddingTop: '16px' }}>
            <h4 style={{ fontSize: '14px', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Link2 size={16} style={{ color: 'var(--accent)' }} />
              <span>Pair with KyRecovery Central Instance</span>
            </h4>
            <p style={{ color: 'var(--ink)', fontSize: '12px', marginBottom: '12px' }}>
              Enter a 6-digit pairing code generated in your KyRecovery dashboard.
            </p>

            <form onSubmit={handlePairRemote} style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <input
                type="url"
                placeholder="https://recovery.internal:8080"
                value={remoteUrl}
                onChange={(e) => setRemoteUrl(e.target.value)}
                required
              />
              <div style={{ display: 'flex', gap: '8px' }}>
                <input
                  type="text"
                  placeholder="6-Digit PIN (e.g. 849201)"
                  value={pairCode}
                  onChange={(e) => setPairCode(e.target.value)}
                  style={{ fontFamily: 'var(--font-mono)', letterSpacing: '2px' }}
                  required
                />
                <button type="submit" disabled={pairingLoading} style={{ flexShrink: 0 }}>
                  {pairingLoading ? 'Pairing...' : 'Claim & Pair'}
                </button>
              </div>
            </form>

            {pairStatus && (
              <p
                style={{
                  fontSize: '12px',
                  color: pairStatus.includes('Successfully') ? 'var(--success)' : 'var(--danger)',
                  marginTop: '8px',
                }}
              >
                {pairStatus}
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
