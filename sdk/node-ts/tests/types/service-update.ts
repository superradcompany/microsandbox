import type { Service } from "../../dist/service.js";

declare const service: Service;

void service.update({ target: { sandbox: "web", port: 8080 } });

// @ts-expect-error target is required.
void service.update({});

// @ts-expect-error update accepts an options object, not a builder callback.
void service.update((update) => update);
