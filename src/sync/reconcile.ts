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

  // Paths already queued for upsert (e.g. conflict copies created by the pull
  // above, or local edits queued before a crash) must not be re-enqueued under a
  // second fileId — that would create two remote rows sharing one pathId. The
  // queue is durable, so this also covers queued-but-unpushed items from a prior
  // session.
  const queuedUpsertPaths = new Set(
    d.state.queueItems().filter((q) => q.op === "upsert").map((q) => q.path),
  );

  // Local-only or content-differing files → enqueue push.
  const seen = new Set<string>();
  for (const f of await d.vault.list()) {
    seen.add(f.path);
    if (queuedUpsertPaths.has(f.path)) continue;
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
