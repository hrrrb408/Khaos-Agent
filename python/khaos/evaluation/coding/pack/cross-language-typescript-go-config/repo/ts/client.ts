export type Config = { timeoutMs: number; retries: number };

export function encode(config: Config) { return JSON.stringify(config); }
