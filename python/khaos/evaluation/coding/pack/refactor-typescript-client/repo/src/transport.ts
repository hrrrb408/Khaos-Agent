export type Request = { path: string; body: string };

export function send(request: Request): string { return request.body; }
