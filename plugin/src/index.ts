import type { OpenClawPluginApi } from "./types/types.d.ts";
import type {
  PluginHookBeforeToolResultEvent,
  PluginHookBeforeToolResultResult,
  PluginHookToolContext,
} from "./types/types.d.ts";

interface SanitizeResponse {
  original: string;
  sanitized: string;
  redacted: boolean;
  redaction_count: number;
  redacted_types: string[];
  was_blocked: boolean;
}

export default (api: OpenClawPluginApi) => {
  const config = api.pluginConfig || {};
  
  // Service configuration
  const serviceUrl = (config.service_url as string) || "http://localhost:8080/scan";
  const timeoutMs = (config.timeout_ms as number) || 5000;
  const failOpen = config.fail_open !== false;
  const scanEnabled = config.scan_enabled !== false;
  
  // Owner bypass - plugin handles this
  const ownerIds = (config.owner_ids as string[]) || [];
  
  // Excluded tools - plugin handles this
  const excludedTools = (config.excluded_tools as string[]) || [];
  
  // Feature flags
  const features = (config.features as Record<string, boolean>) || {};
  const promptGuardEnabled = features.prompt_guard !== false;
  
  // Scan tier
  const scanTier = (config.scan_tier as number) || 1;
  
  api.logger.info(`Prompt Defender plugin initialized`);
  api.logger.info(`  Service URL: ${serviceUrl}`);
  api.logger.info(`  Features: prompt_guard=${promptGuardEnabled}`);
  api.logger.info(`  Owner IDs: ${ownerIds.length > 0 ? ownerIds.join(', ') : '(none)'}`);
  api.logger.info(`  Excluded tools: ${excludedTools.length > 0 ? excludedTools.join(', ') : '(none)'}`);

  // Check if session should bypass scanning (owner)
  const shouldBypass = (sessionKey?: string): boolean => {
    if (!sessionKey || ownerIds.length === 0) return false;
    return ownerIds.includes(sessionKey);
  };

  // Check if tool should be excluded from scanning
  const isExcluded = (toolName: string): boolean => {
    return excludedTools.includes(toolName);
  };

  // Call the sanitize service (redacts sensitive data instead of blocking)
  const sanitizeContent = async (
    content: unknown
  ): Promise<SanitizeResponse | null> => {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);

      // Convert content to string if needed
      const contentStr = typeof content === 'string' ? content : JSON.stringify(content);

      const response = await fetch(`${serviceUrl}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
        },
        body: contentStr,
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json() as SanitizeResponse;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      api.logger.error(`Sanitize request failed: ${message}`);
      
      if (failOpen) {
        api.logger.warn(`Fail-open: allowing tool result despite sanitize failure`);
        return null;
      }
      
      return {
        original: String(content),
        sanitized: String(content),
        redacted: false,
        redaction_count: 0,
        redacted_types: [],
        was_blocked: true,
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
      
      // Check if prompt_guard feature is enabled
      if (!promptGuardEnabled) {
        api.logger.debug(`[Prompt Defender] prompt_guard feature disabled`);
        return;
      }

      // Check if tool is excluded
      if (isExcluded(toolName)) {
        api.logger.debug(`[Prompt Defender] Tool '${toolName}' is excluded from scanning`);
        return;
      }

      // Check owner bypass
      if (shouldBypass(ctx.sessionKey)) {
        api.logger.info(`[Prompt Defender] Owner bypass for session ${ctx.sessionKey}`);
        return;
      }

      api.logger.info(`[Prompt Defender] Sanitizing tool result: ${toolName} (callId: ${toolCallId})`);

      const result = await sanitizeContent(content);

      if (!result) {
        // Fail-open: allow through
        return;
      }

      // If content was redacted, return the sanitized version
      if (result.redacted && result.sanitized !== result.original) {
        api.logger.info(
          `[Prompt Defender] REDACTED ${toolName}: ${result.redaction_count} redaction(s) - ${result.redacted_types.join(", ")}`
        );
        
        return {
          content: result.sanitized,
        } as PluginHookBeforeToolResultResult;
      }

      // Allow (no redactions needed)
      api.logger.debug(`[Prompt Defender] ALLOWED ${toolName}`);
      return;
    }
  );

  api.logger.info(`Prompt Defender: before_tool_result hook registered`);
};
