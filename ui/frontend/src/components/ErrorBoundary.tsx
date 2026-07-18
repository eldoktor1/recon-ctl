import { Component, type ReactNode } from "react";

// Per-route boundary: a data-shape surprise on one page shows an inline error
// instead of blanking the whole control plane.
export class ErrorBoundary extends Component<
  { children: ReactNode; resetKey?: string },
  { error: Error | null }
> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidUpdate(prev: { resetKey?: string }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null });
    }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="fade-in flex h-full flex-col items-center justify-center text-center">
          <div className="mono text-4xl text-[var(--color-bad)]">⚠</div>
          <h2 className="mt-3 text-lg font-semibold text-[var(--color-ink)]">This page hit an error</h2>
          <p className="mono mt-2 max-w-lg text-xs text-[var(--color-ink-dim)]">{this.state.error.message}</p>
          <button
            onClick={() => this.setState({ error: null })}
            className="mt-4 rounded-md border border-[var(--color-border-bright)] px-4 py-2 text-sm text-[var(--color-ink-dim)] hover:text-[var(--color-ink)]"
          >
            retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
