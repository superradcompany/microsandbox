export type PullPolicy = "always" | "if-missing" | "never";

export const PullPolicies: readonly PullPolicy[] = ["always", "if-missing", "never"] as const;
