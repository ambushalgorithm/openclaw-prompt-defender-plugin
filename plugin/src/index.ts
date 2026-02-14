import type { OpenClawPluginApi } from "./types/types.d.ts";
import type {
  PluginHookBeforeToolResultEvent,
  PluginHookBeforeToolResultResult,
  PluginHookToolContext,
} from "./types/types.d.ts";

interface ScanRequest {
  type: "output";
  tool_name: string;
  content: unknown;
  is_error: boolean;
  duration_ms: number;
}

interface ScanResponse {
  action: "allow" | "block" | "sanitize";
  reason?: string;
  sanitized_content?: unknown;
}

export default (api: OpenClawPluginApi) => {
  const config = api.pluginConfig || {};
  const serviceUrl = (config.service_url as string) || "http://localhost:8080";
  const timeoutMs = (config.timeout_ms as number) || 5000;
  const failOpen = config.fail_open !== false;
  const ownerIds = (config.owner_ids as string[]) || [];
  const scanEnabled = config.scan_enabled !== false;

  api.logger.info(`Prompt Defender plugin initialized (service: ${serviceUrl})`);

  // Call the scanning service
  const scanContent = async (
    event: PluginHookBeforeToolResultEvent
  ): Promise<ScanResponse | null> => {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);

      const response = await fetch(`${serviceUrl}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          type: "output",
          tool_name: event.toolName,
          content: event.content,
          is_error: event.isError,
          duration_ms: event.durationMs,
        } as ScanRequest),
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json() as ScanResponse;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      api.logger.error(`Scan request failed: ${message}`);
      
      if (failOpen) {
        api.logger.warn(`Fail-open: allowing tool result despite scan failure`);
        return null;
      }
      
      return {
        action: "block",
        reason: `Scan service unavailable: ${message}`,
      };
    }
  };

  api.on(
    "before_tool_result",
    async (
      event: PluginHookBeforeToolResultEvent,
      ctx: PluginHookToolContext
    ): Promise<PluginHookBeforeToolResultResult | void> => {
      const { toolName, toolCallId, content, isError } = event;

      // Skip errors
      if (isError) {
        api.logger.debug(`[Prompt Defender] Skipping error result for ${toolName}`);
        return;
      }

      // Check if scanning is disabled
      if (!scanEnabled) {
        api.logger.debug(`[Prompt Defender] Scanning disabled`);
        return;
      }

      api.logger.info(`[Prompt Defender] Scanning tool result: ${toolName} (callId: ${toolCallId})`);

      const result = await scanContent(event);

      if (!result) {
        // Fail-open: allow through
        return;
      }

      if (result.action === "block") {
        api.logger.warn(`[Prompt Defender] BLOCKED ${toolName}: ${result.reason}`);
        return {
          block: true,
          blockReason: result.reason || "Blocked by Prompt Defender",
        } as PluginHookBeforeToolResultResult;
      }

      if (result.action === "sanitize" && result.sanitized_content !== undefined) {
        api.logger.info(`[Prompt Defender] SANITIZED ${toolName}`);
        return {
          content: result.sanitized_content,
        } as PluginHookBeforeToolResultResult;
      }

      // Allow
      api.logger.debug(`[Prompt Defender] ALLOWED ${toolName}`);
      return;
    }
  );

  api.logger.info(`Prompt Defender: before_tool_result hook registered`);
};
