import { Request, send } from "./transport";

export class Client {
  post(path: string, body: string) { return send({ path, body }); }
}
