import { DatabaseWriter } from "../_generated/server";

/**
 * Reserve and return the next monotonic version for a workspace. MUST be
 * called inside a mutation. Relies on Convex's serializable transactions:
 * two concurrent callers cannot read the same counter value and both commit,
 * so versions are unique and gap-free per workspace.
 */
export async function nextVersion(db: DatabaseWriter, workspaceId: string): Promise<number> {
  const counter = await db
    .query("counters")
    .withIndex("by_workspace", (q) => q.eq("workspaceId", workspaceId))
    .unique();
  if (counter === null) {
    throw new Error(`No counter for workspace ${workspaceId}`);
  }
  const version = counter.version + 1;
  await db.patch(counter._id, { version });
  return version;
}
