import type { Deps } from "./push";
import { drainQueue } from "./push";
import { pull } from "./pull";
import { newFileId } from "./state";
import { computeContentTag } from "./codec";

/**
 * Cold-start / reconnect reconcile. Order matters for no-loss: pull remote
 * first, then push local divergences, then tombstone vanished files, then drain.
 */
export async function reconcile(d: Deps): Promise<void> {
  await pull(d);

  // Local-only or content-differing files → enqueue push.
  const seen = new Set<string>();
  for (const f of await d.vault.list()) {
    seen.add(f.path);
    const entry = d.state.getByPath(f.path);
    const tag = await computeContentTag(await d.vault.readBinary(f.path), d.keys);
    if (!entry) {
      d.state.enqueue({ op: "upsert", fileId: newFileId(), path: f.path });
    } else if (entry.contentTag !== tag) {
      d.state.enqueue({ op: "upsert", fileId: entry.fileId, path: f.path });
    }
  }

  // Entries whose local file vanished while we weren't watching → tombstone.
  for (const entry of d.state.allEntries()) {
    if (!seen.has(entry.path)) {
      d.state.enqueue({ op: "tombstone", fileId: entry.fileId, path: entry.path });
    }
  }

  await drainQueue(d);
}
