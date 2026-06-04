import { describe, it, expect } from "vitest";
import { SyncState, newFileId } from "../../src/sync/state";
import type { SyncEntry } from "../../src/sync/ports";

const entry = (over: Partial<SyncEntry> = {}): SyncEntry => ({
  fileId: "f1", path: "a.md", pathId: "pa", type: "note",
  contentTag: "t1", syncedVersion: 1, mtime: 100, ...over,
});

describe("SyncState", () => {
  it("indexes an entry by fileId, pathId, and path", () => {
    const s = new SyncState();
    s.upsertEntry(entry());
    expect(s.getByFileId("f1")?.path).toBe("a.md");
    expect(s.getByPathId("pa")?.fileId).toBe("f1");
    expect(s.getByPath("a.md")?.fileId).toBe("f1");
  });

  it("re-indexes when an entry's path changes (rename)", () => {
    const s = new SyncState();
    s.upsertEntry(entry());
    s.upsertEntry(entry({ path: "b.md", pathId: "pb" }));
    expect(s.getByPath("a.md")).toBeUndefined();
    expect(s.getByPathId("pa")).toBeUndefined();
    expect(s.getByPath("b.md")?.fileId).toBe("f1");
  });

  it("removeEntry clears all indexes", () => {
    const s = new SyncState();
    s.upsertEntry(entry());
    s.removeEntry("f1");
    expect(s.getByFileId("f1")).toBeUndefined();
    expect(s.getByPathId("pa")).toBeUndefined();
    expect(s.getByPath("a.md")).toBeUndefined();
  });

  it("enqueue coalesces repeated changes to one item per fileId, preserving order", () => {
    const s = new SyncState();
    s.enqueue({ op: "upsert", fileId: "f1", path: "a.md" });
    s.enqueue({ op: "upsert", fileId: "f2", path: "b.md" });
    s.enqueue({ op: "tombstone", fileId: "f1", path: "a.md" });
    expect(s.queueItems()).toEqual([
      { op: "tombstone", fileId: "f1", path: "a.md" },
      { op: "upsert", fileId: "f2", path: "b.md" },
    ]);
  });

  it("dequeue removes a single item", () => {
    const s = new SyncState();
    s.enqueue({ op: "upsert", fileId: "f1", path: "a.md" });
    s.enqueue({ op: "upsert", fileId: "f2", path: "b.md" });
    s.dequeue("f1");
    expect(s.queueItems().map((q) => q.fileId)).toEqual(["f2"]);
  });

  it("serialize then deserialize preserves entries, cursor, and queue", () => {
    const s = new SyncState();
    s.cursor = 7;
    s.upsertEntry(entry());
    s.enqueue({ op: "upsert", fileId: "f2", path: "b.md" });
    const restored = SyncState.deserialize(s.serialize());
    expect(restored.cursor).toBe(7);
    expect(restored.getByFileId("f1")?.contentTag).toBe("t1");
    expect(restored.getByPath("a.md")?.fileId).toBe("f1");
    expect(restored.queueItems()).toEqual([{ op: "upsert", fileId: "f2", path: "b.md" }]);
  });

  it("deserialize(null) yields an empty state at cursor 0", () => {
    const s = SyncState.deserialize(null);
    expect(s.cursor).toBe(0);
    expect(s.allEntries()).toEqual([]);
    expect(s.queueItems()).toEqual([]);
  });

  it("newFileId returns a 32-char hex id", () => {
    expect(newFileId()).toMatch(/^[0-9a-f]{32}$/);
    expect(newFileId()).not.toBe(newFileId());
  });
});
