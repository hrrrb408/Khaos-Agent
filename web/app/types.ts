export type ChatMode = "office" | "coding";

export type ChatRole = "user" | "assistant" | "system";

export type ChatMessage = {
  id: string;
  type: "message";
  role: ChatRole;
  content: string;
  createdAt: string;
  isStreaming?: boolean;
};

export type StreamEventName = "tool_call" | "tool_result" | "permission_request" | "error" | "done";

export type StreamEventMessage = {
  id: string;
  type: "event";
  event: StreamEventName;
  data: Record<string, unknown>;
  createdAt: string;
};

export type ConversationItem = ChatMessage | StreamEventMessage;

export type ChatSession = {
  id: string;
  title: string;
  mode: ChatMode;
  created_at: string;
  updated_at: string;
  messages: ConversationItem[];
};

export type ChatSettings = {
  gatewayUrl: string;
  apiKey: string;
  modelName: string;
};

export type DoneStats = {
  totalTokens?: number;
  promptTokens?: number;
  completionTokens?: number;
};
