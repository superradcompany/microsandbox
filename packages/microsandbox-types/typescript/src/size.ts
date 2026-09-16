declare const __mebibytes_brand: unique symbol;

/** A size in mebibytes (1 MiB = 1024 × 1024 bytes). */
export type Mebibytes = number & { readonly [__mebibytes_brand]: "Mebibytes" };

// Preserve the SDK helpers' existing arithmetic. A wire request validates the
// resulting number before converting it to an unsigned integer.
export const KiB = (n: number): Mebibytes => (n / 1024) as Mebibytes;
export const MiB = (n: number): Mebibytes => n as Mebibytes;
export const GiB = (n: number): Mebibytes => (n * 1024) as Mebibytes;
export const TiB = (n: number): Mebibytes => (n * 1024 * 1024) as Mebibytes;
