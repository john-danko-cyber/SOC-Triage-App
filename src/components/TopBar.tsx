import React from 'react';

export type WorkflowStep = 'input' | 'context' | 'results';

interface TopBarProps {
  activeStep: WorkflowStep;
  canAccessContext: boolean;
  canAccessResults: boolean;
  onNavigate: (step: WorkflowStep) => void;
  onOpenReference: () => void;
  onReset: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  activeStep,
  canAccessContext,
  canAccessResults,
  onNavigate,
  onOpenReference,
  onReset,
}) => {
  return (
    <header className="sticky top-0 z-30 border-b border-slate-200 bg-white/95 backdrop-blur-sm">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-8 px-6 py-3.5">
        {/* Zone 1: Single-element Brand Wordmark */}
        <button
          type="button"
          onClick={() => onNavigate('input')}
          className="font-display text-lg font-bold tracking-tight text-slate-950 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 cursor-pointer"
        >
          FCEB SOC Triage
        </button>

        {/* Zone 2: 4 single-line text navigation links */}
        <nav
          aria-label="Triage workflow"
          className="hidden md:flex items-center gap-6 text-sm font-medium"
        >
          <button
            type="button"
            onClick={() => onNavigate('input')}
            className={`whitespace-nowrap shrink-0 py-1 transition-colors cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 ${
              activeStep === 'input'
                ? 'text-slate-950 underline underline-offset-8 decoration-2 decoration-slate-950'
                : 'text-slate-600 hover:text-slate-950 hover:underline hover:underline-offset-8'
            }`}
          >
            Log Input
          </button>

          <button
            type="button"
            disabled={!canAccessContext}
            onClick={() => canAccessContext && onNavigate('context')}
            className={`whitespace-nowrap shrink-0 py-1 transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 ${
              !canAccessContext
                ? 'text-slate-300 cursor-not-allowed'
                : activeStep === 'context'
                  ? 'text-slate-950 underline underline-offset-8 decoration-2 decoration-slate-950 cursor-pointer'
                  : 'text-slate-600 hover:text-slate-950 hover:underline hover:underline-offset-8 cursor-pointer'
            }`}
          >
            Mission Context
          </button>

          <button
            type="button"
            disabled={!canAccessResults}
            onClick={() => canAccessResults && onNavigate('results')}
            className={`whitespace-nowrap shrink-0 py-1 transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 ${
              !canAccessResults
                ? 'text-slate-300 cursor-not-allowed'
                : activeStep === 'results'
                  ? 'text-slate-950 underline underline-offset-8 decoration-2 decoration-slate-950 cursor-pointer'
                  : 'text-slate-600 hover:text-slate-950 hover:underline hover:underline-offset-8 cursor-pointer'
            }`}
          >
            Scorecards
          </button>

          <button
            type="button"
            onClick={onOpenReference}
            className="whitespace-nowrap shrink-0 py-1 text-slate-600 hover:text-slate-950 hover:underline hover:underline-offset-8 transition-colors cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
          >
            Playbook Reference
          </button>
        </nav>

        {/* Zone 3: 1 Primary Action */}
        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={onReset}
            className="rounded-lg bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
          >
            New Triage
          </button>
        </div>
      </div>
    </header>
  );
};
