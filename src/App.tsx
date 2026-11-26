/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useState } from 'react';
import { TopBar, type WorkflowStep } from './components/TopBar';
import { LogInputStage, type UploadedLogFile } from './components/LogInputStage';
import { MissionContextStage } from './components/MissionContextStage';
import { ScorecardView } from './components/ScorecardView';
import { PlaybookReferenceModal } from './components/PlaybookReferenceModal';
import type {
  LogInspectionResult,
  MissionContextInput,
  TriageAnalysisResponse,
} from './types/triage';

const DEFAULT_CONTEXT: MissionContextInput = {
  missionCritical: 'unknown',
  piiExposure: 'unknown',
  authorizedActivity: 'unknown',
  ictContractor: 'unknown',
  skippedAll: false,
};

export interface ServerDocsHealth {
  playbookAvailable: boolean;
  ncissAvailable: boolean;
  fingAvailable: boolean;
}

export default function App() {
  const [activeStep, setActiveStep] = useState<WorkflowStep>('input');
  const [pastedLogs, setPastedLogs] = useState('');
  const [uploadedFiles, setUploadedFiles] = useState<UploadedLogFile[]>([]);
  const [docsHealth, setDocsHealth] = useState<ServerDocsHealth | null>(null);

  const [inspection, setInspection] = useState<LogInspectionResult | null>(null);
  const [contextAnswers, setContextAnswers] = useState<MissionContextInput>(DEFAULT_CONTEXT);
  const [analysisResult, setAnalysisResult] = useState<TriageAnalysisResponse | null>(null);

  const [isInspecting, setIsInspecting] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisStatusMessage, setAnalysisStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [referenceOpen, setReferenceOpen] = useState(false);

  useEffect(() => {
    let active = true;
    fetch('/api/health')
      .then((res) => res.json())
      .then(
        (data: {
          playbookAvailable?: boolean;
          ncissAvailable?: boolean;
          fingAvailable?: boolean;
        }) => {
          if (active) {
            setDocsHealth({
              playbookAvailable: Boolean(data.playbookAvailable),
              ncissAvailable: Boolean(data.ncissAvailable),
              fingAvailable: Boolean(data.fingAvailable),
            });
          }
        }
      )
      .catch(() => {
        if (active) {
          setDocsHealth(null);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  const buildCombinedLogs = (): string => {
    const sections: string[] = [];
    if (pastedLogs.trim()) {
      sections.push(`=== PASTED LOG BUFFER ===\n${pastedLogs.trim()}`);
    }
    uploadedFiles.forEach((f) => {
      sections.push(`=== FILE: ${f.name} ===\n${f.content.trim()}`);
    });
    return sections.join('\n\n');
  };

  const runAnalysis = async (
    rawLogs: string,
    finalContext: MissionContextInput,
    detectedContext?: LogInspectionResult['clearContextFromLogs']
  ) => {
    setErrorMessage(null);
    setAnalysisStatusMessage('Preparing deterministic telemetry summary & CISA triage call...');
    setIsAnalyzing(true);
    try {
      const res = await fetch('/api/triage/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          rawLogs,
          contextAnswers: finalContext,
          detectedContext,
          streamProgress: false,
        }),
      });

      const contentType = res.headers.get('content-type') || '';

      if (contentType.includes('text/event-stream') && res.body) {
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let finalData: TriageAnalysisResponse | null = null;
        let streamError: string | null = null;

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });

          let boundaryIndex: number;
          while ((boundaryIndex = buffer.indexOf('\n\n')) !== -1) {
            const rawEvent = buffer.slice(0, boundaryIndex);
            buffer = buffer.slice(boundaryIndex + 2);

            let eventType = 'message';
            const dataLines: string[] = [];
            for (const line of rawEvent.split('\n')) {
              if (line.startsWith('event:')) {
                eventType = line.slice(6).trim();
              } else if (line.startsWith('data:')) {
                dataLines.push(line.slice(5).trim());
              }
            }
            const dataText = dataLines.join('\n');
            if (!dataText) continue;

            const parsed = JSON.parse(dataText) as Record<string, unknown>;
            if (eventType === 'status' && typeof parsed.message === 'string') {
              setAnalysisStatusMessage(parsed.message);
            } else if (eventType === 'result') {
              finalData = parsed as unknown as TriageAnalysisResponse;
            } else if (eventType === 'error') {
              streamError =
                typeof parsed.error === 'string' ? parsed.error : 'Analysis failed.';
            }
          }
        }

        if (streamError) {
          throw new Error(streamError);
        }
        if (!finalData) {
          throw new Error('Server closed connection before delivering triage scorecards.');
        }

        setAnalysisResult(finalData);
        setActiveStep('results');
      } else {
        const data = (await res.json()) as TriageAnalysisResponse & { error?: string };
        if (!res.ok) {
          throw new Error(data.error || `Server returned ${res.status}`);
        }
        setAnalysisResult(data);
        setActiveStep('results');
      }
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Failed to analyze logs.');
    } finally {
      setIsAnalyzing(false);
      setAnalysisStatusMessage(null);
    }
  };

  const handleInspectLogs = async () => {
    const rawLogs = buildCombinedLogs();
    if (!rawLogs.trim()) return;

    setErrorMessage(null);
    setIsInspecting(true);
    try {
      const res = await fetch('/api/triage/inspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawLogs }),
      });
      const data = (await res.json()) as LogInspectionResult & { error?: string };
      if (!res.ok) {
        throw new Error(data.error || `Inspection failed with status ${res.status}`);
      }

      setInspection(data);
      const detected = data.clearContextFromLogs;
      const prefilledContext: MissionContextInput = {
        missionCritical: detected.missionCritical.detected
          ? detected.missionCritical.suggestedValue
          : 'unknown',
        piiExposure: detected.piiExposure.detected
          ? detected.piiExposure.suggestedValue
          : 'unknown',
        authorizedActivity: detected.authorizedActivity.detected
          ? detected.authorizedActivity.suggestedValue
          : 'unknown',
        ictContractor: detected.ictContractor.detected
          ? detected.ictContractor.suggestedValue
          : 'unknown',
        skippedAll: false,
      };
      setContextAnswers(prefilledContext);

      if (data.needsAnalystContextPrompt) {
        setActiveStep('context');
      } else {
        await runAnalysis(rawLogs, prefilledContext, detected);
      }
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Failed to inspect logs.');
    } finally {
      setIsInspecting(false);
    }
  };

  const handleSkipAllAndAnalyze = () => {
    const rawLogs = buildCombinedLogs();
    const skippedContext: MissionContextInput = {
      missionCritical: 'unknown',
      piiExposure: 'unknown',
      authorizedActivity: 'unknown',
      ictContractor: contextAnswers.ictContractor,
      skippedAll: true,
    };
    setContextAnswers(skippedContext);
    void runAnalysis(rawLogs, skippedContext, inspection?.clearContextFromLogs);
  };

  const handleConfirmAndAnalyze = () => {
    const rawLogs = buildCombinedLogs();
    void runAnalysis(rawLogs, contextAnswers, inspection?.clearContextFromLogs);
  };

  const handleReset = () => {
    setPastedLogs('');
    setUploadedFiles([]);
    setInspection(null);
    setContextAnswers(DEFAULT_CONTEXT);
    setAnalysisResult(null);
    setErrorMessage(null);
    setAnalysisStatusMessage(null);
    setActiveStep('input');
  };

  const handleAddLogFiles = (incoming: UploadedLogFile[]) => {
    setUploadedFiles((prev) => {
      const byName = new Map<string, UploadedLogFile>();
      prev.forEach((f) => byName.set(f.name, f));
      incoming.forEach((f) => byName.set(f.name, f));
      return Array.from(byName.values());
    });
    setInspection(null);
    setAnalysisResult(null);
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col">
      <TopBar
        activeStep={activeStep}
        canAccessContext={Boolean(inspection)}
        canAccessResults={Boolean(analysisResult)}
        onNavigate={(step) => {
          setErrorMessage(null);
          setActiveStep(step);
        }}
        onOpenReference={() => setReferenceOpen(true)}
        onReset={handleReset}
      />

      <main className="flex-1 pb-12">
        {activeStep === 'input' && (
          <LogInputStage
            pastedLogs={pastedLogs}
            uploadedFiles={uploadedFiles}
            docsHealth={docsHealth}
            isInspecting={isInspecting || isAnalyzing}
            statusMessage={analysisStatusMessage}
            errorMessage={errorMessage}
            onPastedLogsChange={(val) => {
              setPastedLogs(val);
              setInspection(null);
              setAnalysisResult(null);
            }}
            onAddLogFiles={handleAddLogFiles}
            onRemoveLogFile={(id) => {
              setUploadedFiles((prev) => prev.filter((f) => f.id !== id));
              setInspection(null);
              setAnalysisResult(null);
            }}
            onClearAllLogFiles={() => {
              setUploadedFiles([]);
              setInspection(null);
              setAnalysisResult(null);
            }}
            onSubmitLogs={() => void handleInspectLogs()}
            onOpenReference={() => setReferenceOpen(true)}
          />
        )}

        {activeStep === 'context' && inspection && (
          <MissionContextStage
            inspection={inspection}
            context={contextAnswers}
            isAnalyzing={isAnalyzing}
            statusMessage={analysisStatusMessage}
            errorMessage={errorMessage}
            onChangeContext={setContextAnswers}
            onBackToInput={() => setActiveStep('input')}
            onSkipAllAndAnalyze={handleSkipAllAndAnalyze}
            onConfirmAndAnalyze={handleConfirmAndAnalyze}
          />
        )}

        {activeStep === 'results' && analysisResult && (
          <ScorecardView
            result={analysisResult}
            onAdjustContext={() => setActiveStep('context')}
            onBackToLogs={() => setActiveStep('input')}
          />
        )}
      </main>

      <PlaybookReferenceModal
        open={referenceOpen}
        onClose={() => setReferenceOpen(false)}
      />
    </div>
  );
}
