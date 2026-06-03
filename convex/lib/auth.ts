import { DatabaseReader } from "../_generated/server";
import { Doc } from "../_generated/dataModel";

/** Constant-time comparison of two equal-length hex strings. Returns false
 *  immediately on length mismatch (length is not secret here). */
function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Authenticate a request against a workspace's sync-key verifier and return
 * the workspace document. Throws "Unauthorized" for both an unknown workspace
 * and a bad key (same error). Workspace existence is observable via timing,
 * which is acceptable: workspaceId is not secret. Works with a query or a
 * mutation ctx — pass `ctx.db`. DatabaseWriter extends DatabaseReader.
 */
export async function authenticate(
  db: DatabaseReader,
  workspaceId: string,
  syncKey: string,
): Promise<Doc<"workspaces">> {
  const workspace = await db
    .query("workspaces")
    .withIndex("by_workspace", (q) => q.eq("workspaceId", workspaceId))
    .unique();
  if (workspace === null) {
    throw new Error("Unauthorized");
  }
  const presentedHash = await sha256Hex(syncKey);
  if (!timingSafeEqualHex(presentedHash, workspace.syncKeyHash)) {
    throw new Error("Unauthorized");
  }
  return workspace;
}
