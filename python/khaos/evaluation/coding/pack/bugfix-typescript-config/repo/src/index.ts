import { Config, readEnabled } from "./config";

export function load(config: Partial<Config>) { return readEnabled(config); }
