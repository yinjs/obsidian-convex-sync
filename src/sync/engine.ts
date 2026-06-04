import type { Subkeys } from "../crypto";
import type { Clock, RemotePort, StatePort, VaultPort } from "./ports";
import { SyncState, newFileId } from "./state";
import { drainQueue, type Deps } from "./push";
import { pull } from "./pull";
import { reconcile } from "./reconcile";

export interface EnginePorts {
  vault: VaultPort;
  remote: RemotePort;
  statePort: StatePort;
  clock: Clock;
}

/**
 * Orchestrates sync. Timer-free and subscription-free: the plugin shell (Plan 4)
 * owns the debounce timer and the Convex reactive trigger that call sync().
 */
export class SyncEngine {
  private constructor(
    private readonly ports: EnginePorts,
    private readonly deps: Deps,
  ) {}

  static async create(ports: EnginePorts, keys: Subkeys): Promise<SyncEngine> {
    const state = SyncState.deserialize(await ports.statePort.load());
    const deps: Deps = { vault: ports.vault, remote: ports.remote, state, keys, clock: ports.clock };
    return new SyncEngine(ports, deps);
  }

  /** Record a create/modify. Reuses the fileId already known for this path. */
  notifyChange(path: string): void {
    const fileId = this.deps.state.getByPath(path)?.fileId ?? newFileId();
    this.deps.state.enqueue({ op: "upsert", fileId, path });
  }

  /** Record a delete. No-op if the path is unknown. */
  notifyDelete(path: string): void {
    const entry = this.deps.state.getByPath(path);
    if (!entry) return;
    this.deps.state.enqueue({ op: "tombstone", fileId: entry.fileId, path });
  }

  /** Record a rename: same fileId, new path (one metadata update server-side). */
  notifyRename(from: string, to: string): void {
    const fileId = this.deps.state.getByPath(from)?.fileId ?? newFileId();
    this.deps.state.enqueue({ op: "upsert", fileId, path: to });
  }

  /** Drain the outbound queue, pull remote changes, persist. */
  async sync(): Promise<void> {
    await drainQueue(this.deps);
    await pull(this.deps);
    await this.persist();
  }

  /** Cold-start / reconnect reconcile, then persist. */
  async reconcile(): Promise<void> {
    await reconcile(this.deps);
    await this.persist();
  }

  private async persist(): Promise<void> {
    await this.ports.statePort.save(this.deps.state.serialize());
  }
}
