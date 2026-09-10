export type Config = { enabled: boolean; retries: number };

export function readEnabled(input: Partial<Config>): boolean {
  return input.enabled || true;
}
