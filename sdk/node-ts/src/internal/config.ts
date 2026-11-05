/** Convert schema field names without rewriting dictionary keys owned by callers. */
export function remapKeysToCamel(value: any, dictionary = false): any {
  if (Array.isArray(value)) return value.map((item) => remapKeysToCamel(item));
  if (value && typeof value === "object") {
    // fromEntries also preserves an own "__proto__" key without changing the prototype.
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [
      dictionary ? key : key.replace(/_([a-z0-9])/g, (_match, c: string) => c.toUpperCase()),
      remapKeysToCamel(child, !dictionary && (key === "scripts" || key === "labels")),
    ]));
  }
  return value;
}
